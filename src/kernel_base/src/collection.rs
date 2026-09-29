//! RBSlabIO / LLSlabIO — інтрузивні колекції (RBTree та LinkedList), вузли
//! яких розміщені в slab-алокаторі (`attachable_slab_allocator`).
//!
//! ВИПРАВЛЕННЯ відносно попередньої версії:
//! 1. `intrusive_adapter!` — синтаксис поля посилання: `field => LinkType`
//!    (самe так вимагає макрос intrusive-collections 0.10, див. його доки:
//!    `intrusive_adapter!(Adapter = Pointer: Value { link_field => LinkType })`).
//!    Форма `field: LinkType` цим макросом НЕ парситься — не «виправляйте»
//!    код на неї.
//! 2. `KeyAdapter<'_>` — явний lifetime `<'a>` у реалізації.
//! 3. `insert`: запис через `core::ptr::write` у неініціалізовану пам'ять,
//!    яку повертає `cache.alloc()`.
//! 4. `remove`: слот повертається в slab через `SlabBox<MaybeUninit<Entry>>`
//!    (`free_slot_no_drop`), тому дропається лише сам слот, а не K/V —
//!    вилучені K і V лишаються у володінні викликача `remove`.
//! 5. `Drop` для `RBSlabIO`/`LLSlabIO`: значення, що лишились у колекції на
//!    момент знищення, коректно дропаються через `SlabBox<Entry>`
//!    (`drop_value_and_free_slot`): рівно один `drop_in_place` + `free_slot`.
//! 6. `UnsafeRef::into_raw(entry)` замість `entry.as_ref() as *const _ as *mut _`
//!    (без проміжного спільного посилання, без lint `invalid_reference_casting`).
//! 7. `get(&self, key: &K) -> Option<&V>` для `RBSlabIO` — пошук без вилучення
//!    з дерева, потрібен для надбудов, де стан V мінливий через атомарні поля.
//! 8. ДОДАНО `LLSlabIO<V, ATOMIC>` — той самий підхід (slab + intrusive), але
//!    на основі `LinkedList` замість `RBTree`: двобічна черга/дек без ключів,
//!    з `push_front/push_back/pop_front/pop_back/front/back`. Хелпери
//!    `free_slot_no_drop`/`drop_value_and_free_slot` вже були написані
//!    узагальнено (generic `<E>`), тож перевикористані без жодних змін.
//!    Атомарний лінк для списку — `LinkedListAtomicLink` (той самий підхід,
//!    що й `RBTreeAtomicLink` для дерева).

use attachable_slab_allocator::{SlabBox, SlabCache, SlabError, locks::NoLock};
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use intrusive_collections::{
    KeyAdapter, LinkedList, LinkedListAtomicLink, LinkedListLink, RBTree, RBTreeAtomicLink,
    RBTreeLink, UnsafeRef, intrusive_adapter,
};

// ======================================================================
// Спільні хелпери (використовуються і RBSlabIO, і LLSlabIO)
// ======================================================================

/// Повертає слот у slab-алокатор, НЕ викликаючи деструктори значення.
///
/// # Safety
/// - `ptr` — валідний слот, раніше виділений зі slab-кешу з розміром сторінки 4096;
/// - значення за `ptr` вже «переміщено» (наприклад, через `ptr::read`), тож його
///   деструктори не повинні викликатися повторно.
///
/// Механізм: `MaybeUninit<E>` має той самий розмір і вирівнювання, що й `E`,
/// але не має drop glue. Тому `SlabBox::drop` виконає лише `free_slot`
/// (повернення слота в slab) — без `drop_in_place` для вмісту E.
unsafe fn free_slot_no_drop<E>(ptr: *mut E) { unsafe {
    let uninit_ptr: NonNull<MaybeUninit<E>> = NonNull::new_unchecked(ptr).cast::<MaybeUninit<E>>();
    let _box: SlabBox<MaybeUninit<E>, NoLock, 4096> = SlabBox::new(uninit_ptr);
    drop(_box); // лише free_slot, деструктори вмісту не викликаються
}}

/// Коректно знищує значення в слоті (деструктори вмісту викликаються один раз)
/// і повертає пам'ять у slab-алокатор.
///
/// # Safety
/// - `ptr` — валідний слот, раніше виділений зі slab-кешу з розміром сторінки 4096;
/// - значення за `ptr` є ініціалізованим і ним більше ніхто не володіє.
unsafe fn drop_value_and_free_slot<E>(ptr: *mut E) { unsafe {
    let _box: SlabBox<E, NoLock, 4096> = SlabBox::new(NonNull::new_unchecked(ptr));
    drop(_box); // drop_in_place::<E> + free_slot
}}

// ======================================================================
// RBSlabIO — інтрузивне red-black дерево з ключем K
// ======================================================================

pub struct SlabInterfaceRBEntry<K, V> {
    pub key: K,
    pub value: V,
    link: RBTreeLink,
}

pub struct AtomicSlabInterfaceRBEntry<K, V> {
    pub key: K,
    pub value: V,
    link: RBTreeAtomicLink,
}

intrusive_adapter!(
    pub ASlabIORB<K, V> = UnsafeRef<SlabInterfaceRBEntry<K, V>>:
        SlabInterfaceRBEntry<K, V> { link=> RBTreeLink }
);

intrusive_adapter!(
    pub AAtomicSlabIORB<K, V> = UnsafeRef<AtomicSlabInterfaceRBEntry<K, V>>:
        AtomicSlabInterfaceRBEntry<K, V> { link=> RBTreeAtomicLink }
);

impl<'a, K: Ord + Clone, V> KeyAdapter<'a> for ASlabIORB<K, V> {
    type Key = K;

    fn get_key(&self, value: &'a SlabInterfaceRBEntry<K, V>) -> K {
        value.key.clone()
    }
}

impl<'a, K: Ord + Clone, V> KeyAdapter<'a> for AAtomicSlabIORB<K, V> {
    type Key = K;
    fn get_key(&self, value: &'a AtomicSlabInterfaceRBEntry<K, V>) -> K {
        value.key.clone()
    }
}

pub type NonAtomicRBCache<K, V> = SlabCache<SlabInterfaceRBEntry<K, V>, NoLock, 4096>;
pub  type AtomicRBCache<K, V> = SlabCache<AtomicSlabInterfaceRBEntry<K, V>, NoLock, 4096>;

pub struct RBSlabIO<K: Ord + Clone, V, const ATOMIC: bool> {
    inner: RBSlabIOInner<K, V, ATOMIC>,
}

enum RBSlabIOInner<K, V, const ATOMIC: bool> {
    NonAtomic {
        cache: NonAtomicRBCache<K, V>,
        rbtree: RBTree<ASlabIORB<K, V>>,
    },
    Atomic {
        cache: AtomicRBCache<K, V>,
        rbtree: RBTree<AAtomicSlabIORB<K, V>>,
    },
}

impl<K: Ord + Clone, V, const ATOMIC: bool> RBSlabIO<K, V, ATOMIC> {
    pub fn new() -> Result<Self, SlabError> {
        if ATOMIC {
            Ok(Self {
                inner: RBSlabIOInner::Atomic {
                    cache: AtomicRBCache::new()?,
                    rbtree: RBTree::new(AAtomicSlabIORB::new()),
                },
            })
        } else {
            Ok(Self {
                inner: RBSlabIOInner::NonAtomic {
                    cache: NonAtomicRBCache::new()?,
                    rbtree: RBTree::new(ASlabIORB::new()),
                },
            })
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Result<(), SlabError> {
        match &mut self.inner {
            RBSlabIOInner::NonAtomic { cache, rbtree } => {
                let slab_box = cache.alloc()?;
                // alloc() повертає НЕІНІЦІАЛІЗОВАНУ пам'ять — пишемо через
                // ptr::write, а не `*slab_box = ...` (це дропнуло б «старе»
                // неініціалізоване значення — UB).
                unsafe {
                    core::ptr::write(
                        slab_box.as_ptr(),
                        SlabInterfaceRBEntry {
                            key,
                            value,
                            link: RBTreeLink::new(),
                        },
                    );
                }

                let raw_ptr = slab_box.as_ptr();
                // "Забуваємо" slab_box, щоб пам'ять не повернулася в аллокатор
                // при виході зі скоупа: володіння переходить до RBTree.
                core::mem::forget(slab_box);

                let unsafe_ref = unsafe { UnsafeRef::from_raw(raw_ptr as *const _) };
                rbtree.insert(unsafe_ref);
                Ok(())
            }
            RBSlabIOInner::Atomic { cache, rbtree } => {
                let slab_box = cache.alloc()?;
                unsafe {
                    core::ptr::write(
                        slab_box.as_ptr(),
                        AtomicSlabInterfaceRBEntry {
                            key,
                            value,
                            link: RBTreeAtomicLink::new(),
                        },
                    );
                }

                let raw_ptr = slab_box.as_ptr();
                core::mem::forget(slab_box);

                let unsafe_ref = unsafe { UnsafeRef::from_raw(raw_ptr as *const _) };
                rbtree.insert(unsafe_ref);
                Ok(())
            }
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<(K, V)> {
        match &mut self.inner {
            RBSlabIOInner::NonAtomic { cache: _, rbtree } => {
                let mut cursor = rbtree.find_mut(key);
                let entry = cursor.remove()?;
                // into_raw дає *mut Entry без проміжного спільного посилання
                // (безпечно й без lint invalid_reference_casting).
                let ptr = UnsafeRef::into_raw(entry);

                // Витягуємо K і V у володіння (біти лишаються в слоті,
                // але їх більше ніхто не дропне).
                let kv = unsafe { core::ptr::read(ptr) };

                // Повертаємо слот у slab БЕЗ деструкторів K/V.
                unsafe { free_slot_no_drop(ptr) };

                Some((kv.key, kv.value))
            }
            RBSlabIOInner::Atomic { cache: _, rbtree } => {
                let mut cursor = rbtree.find_mut(key);
                let entry = cursor.remove()?;
                let ptr = UnsafeRef::into_raw(entry);

                let kv = unsafe { core::ptr::read(ptr) };
                unsafe { free_slot_no_drop(ptr) };

                Some((kv.key, kv.value))
            }
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        match &self.inner {
            // Курсор не має методу is_some(), використовуємо !is_null()
            RBSlabIOInner::NonAtomic { rbtree, .. } => !rbtree.find(key).is_null(),
            RBSlabIOInner::Atomic { rbtree, .. } => !rbtree.find(key).is_null(),
        }
    }

    /// Пошук значення за ключем БЕЗ вилучення з дерева.
    ///
    /// На відміну від `remove`, тут не потрібне `&mut self` — достатньо
    /// спільного посилання, оскільки виклик лише читає дерево. Це дозволяє
    /// надбудовам (capability-таблиця тощо) тримати всю мінливість стану V
    /// в атомарних полях і оновлювати їх конкурентно через `&V`, не чіпаючи
    /// структуру самого дерева.
    pub fn get(&self, key: &K) -> Option<&V> {
        match &self.inner {
            RBSlabIOInner::NonAtomic { rbtree, .. } => {
                rbtree.find(key).get().map(|entry| &entry.value)
            }
            RBSlabIOInner::Atomic { rbtree, .. } => {
                rbtree.find(key).get().map(|entry| &entry.value)
            }
        }
    }

    /// Итерация по значениям дерева (в порядке ключей) без извлечения.
    ///
    /// Отдельно от `Iterator` сознательно (см. комментарий LLSlabIO):
    /// intrusive-ссылки узлов живут в slab и не переживают вынимание,
    /// обход — только по курсору под &self. Нужен был IPC-транспорту
    /// (обратный поиск GTcb → task_cap_id).
    pub fn for_each<F: FnMut(&V)>(&self, mut f: F) {
        match &self.inner {
            RBSlabIOInner::NonAtomic { rbtree, .. } => {
                let mut cursor = rbtree.front();
                while let Some(entry) = cursor.get() {
                    f(&entry.value);
                    cursor.move_next();
                }
            }
            RBSlabIOInner::Atomic { rbtree, .. } => {
                let mut cursor = rbtree.front();
                while let Some(entry) = cursor.get() {
                    f(&entry.value);
                    cursor.move_next();
                }
            }
        }
    }
}
// ПРИМЕЧАНИЕ о get_mut: интрузивное дерево принципиально не даёт
// &mut V через &self-доступ (узлы разделяются курсорами), а &mut self
// вариант не нужен — вся мутация значений в этом ядре идёт через
// атомарные поля самих V (см. комментарий у Namespace: "get_mut
// принципиально не предоставляется"). Прежняя заглушка
// `pub fn get_mut -> unimplemented!()` удалена: мёртвый код с panic
// в no_std-ядре — мина (один вызов убивает всю систему).
// Drop для запобігання витоку slab-пам'яті при знищенні RBSlabIO.
// UnsafeRef не звільняє пам'ять автоматично, тож вичищаємо дерево вручну.
impl<K: Ord + Clone, V, const ATOMIC: bool> Drop for RBSlabIO<K, V, ATOMIC> {
    fn drop(&mut self) {
        match &mut self.inner {
            RBSlabIOInner::NonAtomic { cache: _, rbtree } => {
                while !rbtree.is_empty() {
                    let mut cursor = rbtree.front_mut();
                    if let Some(entry) = cursor.remove() {
                        let ptr = UnsafeRef::into_raw(entry);
                        // Значення ще живі — дропаємо K і V та повертаємо
                        // слот у slab (один дроп, без UB).
                        unsafe { drop_value_and_free_slot(ptr) };
                    }
                }
            }
            RBSlabIOInner::Atomic { cache: _, rbtree } => {
                while !rbtree.is_empty() {
                    let mut cursor = rbtree.front_mut();
                    if let Some(entry) = cursor.remove() {
                        let ptr = UnsafeRef::into_raw(entry);
                        unsafe { drop_value_and_free_slot(ptr) };
                    }
                }
            }
        }
    }
}

// ======================================================================
// LLSlabIO — інтрузивний двобічний список (LinkedList) без ключів,
// вузли — теж у slab-алокаторі. Push/pop з обох кінців за O(1).
// ======================================================================

pub struct SlabInterfaceLLEntry<V> {
    pub value: V,
    link: LinkedListLink,
}

pub struct AtomicSlabInterfaceLLEntry<V> {
    pub value: V,
    link: LinkedListAtomicLink,
}

intrusive_adapter!(
    pub ASlabIOLL<V> = UnsafeRef<SlabInterfaceLLEntry<V>>:
        SlabInterfaceLLEntry<V> { link=> LinkedListLink }
);

intrusive_adapter!(
    pub AAtomicSlabIOLL<V> = UnsafeRef<AtomicSlabInterfaceLLEntry<V>>:
        AtomicSlabInterfaceLLEntry<V> { link=> LinkedListAtomicLink }
);

type NonAtomicLLCache<V> = SlabCache<SlabInterfaceLLEntry<V>, NoLock, 4096>;
type AtomicLLCache<V> = SlabCache<AtomicSlabInterfaceLLEntry<V>, NoLock, 4096>;

// На відміну від RBSlabIO, тут не потрібні бонуси Ord + Clone — LinkedList
// не має ключа і не потребує KeyAdapter.
pub struct LLSlabIO<V, const ATOMIC: bool> {
    inner: LLSlabIOInner<V, ATOMIC>,
}

enum LLSlabIOInner<V, const ATOMIC: bool> {
    NonAtomic {
        cache: NonAtomicLLCache<V>,
        list: LinkedList<ASlabIOLL<V>>,
    },
    Atomic {
        cache: AtomicLLCache<V>,
        list: LinkedList<AAtomicSlabIOLL<V>>,
    },
}

impl<V, const ATOMIC: bool> LLSlabIO<V, ATOMIC> {
    pub fn new() -> Result<Self, SlabError> {
        if ATOMIC {
            Ok(Self {
                inner: LLSlabIOInner::Atomic {
                    cache: AtomicLLCache::new()?,
                    list: LinkedList::new(AAtomicSlabIOLL::new()),
                },
            })
        } else {
            Ok(Self {
                inner: LLSlabIOInner::NonAtomic {
                    cache: NonAtomicLLCache::new()?,
                    list: LinkedList::new(ASlabIOLL::new()),
                },
            })
        }
    }

    /// Додає елемент на початок списку. O(1).
    pub fn push_front(&mut self, value: V) -> Result<(), SlabError> {
        match &mut self.inner {
            LLSlabIOInner::NonAtomic { cache, list } => {
                let slab_box = cache.alloc()?;
                unsafe {
                    core::ptr::write(
                        slab_box.as_ptr(),
                        SlabInterfaceLLEntry {
                            value,
                            link: LinkedListLink::new(),
                        },
                    );
                }
                let raw_ptr = slab_box.as_ptr();
                core::mem::forget(slab_box);
                let unsafe_ref = unsafe { UnsafeRef::from_raw(raw_ptr as *const _) };
                list.push_front(unsafe_ref);
                Ok(())
            }
            LLSlabIOInner::Atomic { cache, list } => {
                let slab_box = cache.alloc()?;
                unsafe {
                    core::ptr::write(
                        slab_box.as_ptr(),
                        AtomicSlabInterfaceLLEntry {
                            value,
                            link: LinkedListAtomicLink::new(),
                        },
                    );
                }
                let raw_ptr = slab_box.as_ptr();
                core::mem::forget(slab_box);
                let unsafe_ref = unsafe { UnsafeRef::from_raw(raw_ptr as *const _) };
                list.push_front(unsafe_ref);
                Ok(())
            }
        }
    }

    /// Додає елемент у кінець списку. O(1).
    pub fn push_back(&mut self, value: V) -> Result<(), SlabError> {
        match &mut self.inner {
            LLSlabIOInner::NonAtomic { cache, list } => {
                let slab_box = cache.alloc()?;
                unsafe {
                    core::ptr::write(
                        slab_box.as_ptr(),
                        SlabInterfaceLLEntry {
                            value,
                            link: LinkedListLink::new(),
                        },
                    );
                }
                let raw_ptr = slab_box.as_ptr();
                core::mem::forget(slab_box);
                let unsafe_ref = unsafe { UnsafeRef::from_raw(raw_ptr as *const _) };
                list.push_back(unsafe_ref);
                Ok(())
            }
            LLSlabIOInner::Atomic { cache, list } => {
                let slab_box = cache.alloc()?;
                unsafe {
                    core::ptr::write(
                        slab_box.as_ptr(),
                        AtomicSlabInterfaceLLEntry {
                            value,
                            link: LinkedListAtomicLink::new(),
                        },
                    );
                }
                let raw_ptr = slab_box.as_ptr();
                core::mem::forget(slab_box);
                let unsafe_ref = unsafe { UnsafeRef::from_raw(raw_ptr as *const _) };
                list.push_back(unsafe_ref);
                Ok(())
            }
        }
    }

    /// Знімає елемент з початку списку. O(1).
    pub fn pop_front(&mut self) -> Option<V> {
        match &mut self.inner {
            LLSlabIOInner::NonAtomic { cache: _, list } => {
                let entry = list.pop_front()?;
                let ptr = UnsafeRef::into_raw(entry);
                let val = unsafe { core::ptr::read(ptr) };
                unsafe { free_slot_no_drop(ptr) };
                Some(val.value)
            }
            LLSlabIOInner::Atomic { cache: _, list } => {
                let entry = list.pop_front()?;
                let ptr = UnsafeRef::into_raw(entry);
                let val = unsafe { core::ptr::read(ptr) };
                unsafe { free_slot_no_drop(ptr) };
                Some(val.value)
            }
        }
    }

    /// Знімає елемент з кінця списку. O(1).
    pub fn pop_back(&mut self) -> Option<V> {
        match &mut self.inner {
            LLSlabIOInner::NonAtomic { cache: _, list } => {
                let entry = list.pop_back()?;
                let ptr = UnsafeRef::into_raw(entry);
                let val = unsafe { core::ptr::read(ptr) };
                unsafe { free_slot_no_drop(ptr) };
                Some(val.value)
            }
            LLSlabIOInner::Atomic { cache: _, list } => {
                let entry = list.pop_back()?;
                let ptr = UnsafeRef::into_raw(entry);
                let val = unsafe { core::ptr::read(ptr) };
                unsafe { free_slot_no_drop(ptr) };
                Some(val.value)
            }
        }
    }

    /// Спільне посилання на перший елемент, без вилучення.
    pub fn front(&self) -> Option<&V> {
        match &self.inner {
            LLSlabIOInner::NonAtomic { list, .. } => list.front().get().map(|e| &e.value),
            LLSlabIOInner::Atomic { list, .. } => list.front().get().map(|e| &e.value),
        }
    }

    /// Спільне посилання на останній елемент, без вилучення.
    pub fn back(&self) -> Option<&V> {
        match &self.inner {
            LLSlabIOInner::NonAtomic { list, .. } => list.back().get().map(|e| &e.value),
            LLSlabIOInner::Atomic { list, .. } => list.back().get().map(|e| &e.value),
        }
    }

    pub fn is_empty(&self) -> bool {
        match &self.inner {
            LLSlabIOInner::NonAtomic { list, .. } => list.is_empty(),
            LLSlabIOInner::Atomic { list, .. } => list.is_empty(),
        }
    }

    /// Проходить по всіх елементах від початку до кінця, O(n).
    ///
    /// Навмисно не `iter() -> impl Iterator`: NonAtomic- і Atomic-гілки
    /// мають різні конкретні типи ітератора (Iter<ASlabIOLL<V>> vs
    /// Iter<AAtomicSlabIOLL<V>>), а уніфікувати їх можна було б лише через
    /// `Box<dyn Iterator>`, що вимагає `alloc` у цьому no_std/slab-контексті.
    /// `for_each` дає той самий прохід без цієї залежності.
    pub fn for_each<F: FnMut(&V)>(&self, mut f: F) {
        match &self.inner {
            LLSlabIOInner::NonAtomic { list, .. } => {
                for entry in list.iter() {
                    f(&entry.value);
                }
            }
            LLSlabIOInner::Atomic { list, .. } => {
                for entry in list.iter() {
                    f(&entry.value);
                }
            }
        }
    }
}

// Drop для запобігання витоку slab-пам'яті при знищенні LLSlabIO.
impl<V, const ATOMIC: bool> Drop for LLSlabIO<V, ATOMIC> {
    fn drop(&mut self) {
        match &mut self.inner {
            LLSlabIOInner::NonAtomic { cache: _, list } => {
                while let Some(entry) = list.pop_front() {
                    let ptr = UnsafeRef::into_raw(entry);
                    unsafe { drop_value_and_free_slot(ptr) };
                }
            }
            LLSlabIOInner::Atomic { cache: _, list } => {
                while let Some(entry) = list.pop_front() {
                    let ptr = UnsafeRef::into_raw(entry);
                    unsafe { drop_value_and_free_slot(ptr) };
                }
            }
        }
    }
}
