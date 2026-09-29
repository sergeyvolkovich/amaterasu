use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, Fields, Index};

#[proc_macro_derive(SyscallArguments)]
pub fn derive_syscall_arguments(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let (field_count, init_body, get_arg_arms) = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let count = fields.named.len();
                let field_names = fields.named.iter().map(|f| &f.ident);
                let indices = 0..count;
                
                let init = quote! {
                    Self {
                        #(#field_names: r[#indices],)*
                    }
                };
                
                let arms = fields.named.iter().enumerate().map(|(i, f)| {
                    let ident = &f.ident;
                    // Если вдруг поля будут не u64, можно добавить `as u64` или `.into()`
                    quote! { #i => self.#ident }
                });
                
                (count, init, quote! { #(#arms,)* })
            }
            Fields::Unnamed(fields) => {
                let count = fields.unnamed.len();
                let indices = 0..count;
                
                let init = quote! {
                    Self(
                        #(r[#indices],)*
                    )
                };
                
                let arms = (0..count).map(|i| {
                    let idx = Index::from(i);
                    quote! { #i => self.#idx }
                });
                
                (count, init, quote! { #(#arms,)* })
            }
            Fields::Unit => {
                // Для unit-структур (без полей)
                (0, quote! { Self }, quote! {})
            }
        },
        _ => panic!("SyscallArguments can only be derived for structs"),
    };

    let expanded = quote! {
        impl crate::traits::syscall::SyscallArguments for #name {
            const MAX_ARG_COUNT: usize = #field_count;

            fn init_from_regs(r: &[u64]) -> Self {
                #init_body
            }

            fn get_argument<const ID: usize>(&self) -> u64 {
                // Проверка на этапе компиляции (требует Rust 1.79+).
                // Если ID выйдет за пределы, код просто не скомпилируется.
                const { assert!(ID < #field_count, "Argument index out of bounds"); }
                
                match ID {
                    #get_arg_arms
                    _ => unreachable!()
                }
            }
        }
    };

    TokenStream::from(expanded)
}