use core::ptr::NonNull;

use attachable_slab_allocator::SlabError;

use crate::{
    access::{
        AccessManager, CreateTaskError as AccessCreateTaskError,
        DestroyTaskError as AccessDestroyTaskError,
    },
    collection::RBSlabIO,
    task::tcb::{GTcb, TCB},
    traits::memory::MemoryInterfaceUserspace,
};

pub mod deadline;
pub mod irq_wait;
pub mod stats;
pub mod tcb;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskRuntime {
    pub task_cap_id: u64,
    pub task_begin_addr: u64,
    pub task_code_size: u64,
    pub task_stack_size: u64,
    /// Верх начального стека (аргументы задачи); 0 — не установлен.
    pub initial_stack_top: u64,
}

#[derive(Debug)]
pub enum CreateTaskManagerError {
    IdSpaceExhausted,
    Slab(SlabError),
    Access(AccessCreateTaskError),
}

#[derive(Debug)]
pub enum RegisterTaskError {
    NotFound,
    CapabilityRevoked,
    CapabilityDoesNotMatchTcb,
}

#[derive(Debug)]
pub enum DestroyTaskManagerError {
    NotFound,
    /// Capability с таким id существует, но не является задачей.
    NotTask,
    Access(AccessDestroyTaskError),
    InvariantBroken,
}

pub struct TaskManager<UMAP: MemoryInterfaceUserspace> {
    /// GTcb ownership lives here. AccessManager stores only NonNull<GTcb>.
    gtcb_list: RBSlabIO<u64, GTcb<UMAP>, false>,
    /// TCBs are keyed by the capability id that names the task.
    ltcb_list: RBSlabIO<u64, TCB<UMAP>, false>,
    next_gtcb_id: u64,
}

impl<UMAP: MemoryInterfaceUserspace> Default for TaskManager<UMAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<UMAP: MemoryInterfaceUserspace> TaskManager<UMAP> {
    pub fn new() -> Self {
        Self {
            gtcb_list: RBSlabIO::new().expect("failed to allocate GTcb slab"),
            ltcb_list: RBSlabIO::new().expect("failed to allocate TCB slab"),
            next_gtcb_id: 0,
        }
    }

    /// Creates the GTcb first, then publishes a TaskTCB capability pointing
    /// at its stable slab address, and only then publishes the local TCB.
    ///
    /// Any failure before the last step rolls the namespace quota/capability
    /// and GTcb allocation back, keeping the two managers synchronized.
    pub fn create_task(
        &mut self,
        access: &mut AccessManager<UMAP>,
        namespace_id: u64,
        gtcb: GTcb<UMAP>,
    ) -> Result<u64, CreateTaskManagerError> {
        let gtcb_id = self.next_gtcb_id;
        self.next_gtcb_id = self
            .next_gtcb_id
            .checked_add(1)
            .ok_or(CreateTaskManagerError::IdSpaceExhausted)?;

        self.gtcb_list
            .insert(gtcb_id, gtcb)
            .map_err(CreateTaskManagerError::Slab)?;

        let gtcb_owner = NonNull::from(
            self.gtcb_list
                .get(&gtcb_id)
                .expect("GTcb inserted above must be addressable"),
        );

        let task_cap_id = match access.create_task_in_namespace(namespace_id, gtcb_owner) {
            Ok(id) => id,
            Err(error) => {
                let _ = self.gtcb_list.remove(&gtcb_id);
                return Err(CreateTaskManagerError::Access(error));
            }
        };

        let tcb = TCB::new(gtcb_owner, gtcb_id, task_cap_id);

        if let Err(error) = self.ltcb_list.insert(task_cap_id, tcb) {
            // Capability creation has already reserved namespace quota.
            // destroy_task() performs the matching revoke + quota release.
            let _ = access.destroy_task(task_cap_id);
            let _ = self.gtcb_list.remove(&gtcb_id);
            return Err(CreateTaskManagerError::Slab(error));
        }

        Ok(task_cap_id)
    }

    /// Registers scheduler metadata only after verifying that the capability
    /// still points at the exact GTcb owned by this TaskManager.
    pub fn register_task(
        &self,
        access: &AccessManager<UMAP>,
        task_cap_id: u64,
        task_begin_addr: u64,
        task_code_size: u64,
        task_stack_size: u64,
    ) -> Result<TaskRuntime, RegisterTaskError> {
        let tcb = self
            .ltcb_list
            .get(&task_cap_id)
            .ok_or(RegisterTaskError::NotFound)?;

        let capability_gtcb = access
            .get_task_tcb(task_cap_id)
            .ok_or(RegisterTaskError::CapabilityRevoked)?;

        if capability_gtcb != tcb.gtcb_owner() {
            return Err(RegisterTaskError::CapabilityDoesNotMatchTcb);
        }

        tcb.configure_runtime(task_begin_addr, task_code_size, task_stack_size);

        Ok(TaskRuntime {
            task_cap_id,
            task_begin_addr,
            task_code_size,
            task_stack_size,
            initial_stack_top: tcb.initial_stack_top(),
        })
    }

    pub fn get_tcb(&self, task_cap_id: u64) -> Option<&TCB<UMAP>> {
        self.ltcb_list.get(&task_cap_id)
    }

    /// Обратный поиск: task_cap_id задачи, владеющей данным GTcb.
    ///
    /// Нужен IPC-транспорту: capability отправителя резолвится в
    /// `CapabilityObject::TaskTCB` (сырой NonNull<GTcb> получателя), а
    /// реестр эндпоинтов и пересылка capability адресуются глобальным
    /// task_cap_id. Линейный скан slab-таблицы — осознанно: число задач
    /// мало (десятки), а IPC-путь и так под permission_backend-локом.
    pub fn task_cap_id_by_gtcb(&self, gtcb: NonNull<GTcb<UMAP>>) -> Option<u64> {
        let mut found = None;
        self.ltcb_list.for_each(|tcb| {
            if found.is_none() && tcb.gtcb_owner() == gtcb {
                found = Some(tcb.task_cap_id());
            }
        });
        found
    }

    /// Уничтожает задачу одной транзакцией по всем трём сторонам:
    /// capability (AccessManager), локальный TCB и GTcb.
    ///
    /// Синхронизация с capability manager:
    /// - успешный `access.destroy_task()` отзывает capability (tombstone +
    ///   снятие квоты namespace) — после этого локальные записи снимаются
    ///   БЕЗУСЛОВНО, даже при провале сверки указателей: иначе id, отданный
    ///   в очередь переиспользования, мог бы алиасить мёртвый TCB через
    ///   `get_tcb()`;
    /// - если capability уже уничтожена в обход TaskManager (прямой вызов
    ///   AccessManager::destroy_object) или id переиспользован под не-задачу,
    ///   локальные записи по этому id — мусор по определению и снимаются так же;
    /// - ошибки namespace (NamespaceRevoked и т.п.) оставляют задачу живой
    ///   по мнению capability manager — локальное состояние не трогается.
    pub fn destroy_task(
        &mut self,
        access: &mut AccessManager<UMAP>,
        task_cap_id: u64,
    ) -> Result<GTcb<UMAP>, DestroyTaskManagerError> {
        let (gtcb_id, expected_gtcb) = {
            let tcb = self
                .ltcb_list
                .get(&task_cap_id)
                .ok_or(DestroyTaskManagerError::NotFound)?;
            (tcb.gtcb_id(), tcb.gtcb_owner())
        };

        match access.destroy_task(task_cap_id) {
            Ok(destroyed_gtcb) => {
                let gtcb = self.remove_local_task(task_cap_id, gtcb_id)?;

                if destroyed_gtcb != expected_gtcb {
                    // Сверка провалилась: capability указывала на чужой GTcb.
                    // Локальное состояние уже консистентно (записей нет),
                    // сигнализируем о сломанном инварианте.
                    return Err(DestroyTaskManagerError::InvariantBroken);
                }
                debug_assert_eq!(destroyed_gtcb, expected_gtcb);
                Ok(gtcb)
            }
            // Capability уничтожена вне TaskManager — локальные записи
            // остались сиротами; снимаем, чтобы get_tcb() не отдавал мёртвую
            // задачу под id, который capability manager уже переиспользует.
            Err(AccessDestroyTaskError::NotFound) => {
                self.remove_local_task(task_cap_id, gtcb_id)?;
                Err(DestroyTaskManagerError::NotFound)
            }
            Err(AccessDestroyTaskError::NotTask) => {
                self.remove_local_task(task_cap_id, gtcb_id)?;
                Err(DestroyTaskManagerError::NotTask)
            }
            // Задача жива с точки зрения capability manager — ничего не трогаем.
            Err(error) => Err(DestroyTaskManagerError::Access(error)),
        }
    }

    /// Снимает локальные TCB/GTcb записи задачи, чья capability-сторона уже
    /// уничтожена. Вызывать только после того, как capability больше нет —
    /// иначе GTcb-указатель в CapabilityObject::TaskTCB станет висячим.
    fn remove_local_task(
        &mut self,
        task_cap_id: u64,
        gtcb_id: u64,
    ) -> Result<GTcb<UMAP>, DestroyTaskManagerError> {
        self.ltcb_list
            .remove(&task_cap_id)
            .ok_or(DestroyTaskManagerError::InvariantBroken)?;
        let (_, gtcb) = self
            .gtcb_list
            .remove(&gtcb_id)
            .ok_or(DestroyTaskManagerError::InvariantBroken)?;
        Ok(gtcb)
    }
}
