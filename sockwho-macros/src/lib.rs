use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn};

struct Decorator {
    macro_name: proc_macro2::TokenStream,
    context_name: proc_macro2::TokenStream,
    probe_type: &'static str,
}

fn uprobe_decorator() -> Decorator {
    Decorator {
        macro_name: quote! { aya_bpf::macros::uprobe },
        context_name: quote! { aya_bpf::programs::ProbeContext },
        probe_type: "uprobe",
    }
}

fn uretprobe_decorator() -> Decorator {
    Decorator {
        macro_name: quote! { aya_bpf::macros::uretprobe },
        context_name: quote! { aya_bpf::programs::ProbeContext },
        probe_type: "uretprobe",
    }
}

fn tracepoint_decorator() -> Decorator {
    Decorator {
        macro_name: quote! { aya_bpf::macros::tracepoint },
        context_name: quote! { aya_bpf::programs::TracePointContext },
        probe_type: "tracepoint",
    }
}

#[proc_macro_attribute]
pub fn sockwho_uprobe(_args: TokenStream, item: TokenStream) -> TokenStream {
    decorate_item(uprobe_decorator(), item)
}

#[proc_macro_attribute]
pub fn sockwho_uretprobe(_args: TokenStream, item: TokenStream) -> TokenStream {
    decorate_item(uretprobe_decorator(), item)
}

#[proc_macro_attribute]
pub fn sockwho_tracepoint(_args: TokenStream, item: TokenStream) -> TokenStream {
    decorate_item(tracepoint_decorator(), item)
}

fn decorate_item(decorator: Decorator, item: TokenStream) -> TokenStream {
    // TODO: validate signature
    let Decorator { macro_name, context_name, probe_type } = decorator;
    let probe_function = parse_macro_input!(item as ItemFn);
    let probe_function_name = &probe_function.sig.ident;
    let program_name = probe_function_name.to_string();
    let entrypoint_name = format_ident!("{probe_function_name}_{probe_type}_entrypoint");
    let entrypoint = quote!(
        #[#macro_name(name = #program_name)]
        pub fn #entrypoint_name(ctx: #context_name) -> i32 {
            let result = #probe_function_name(ctx);
            match result {
                Ok(()) => 0,
                Err(ret) => ret.into_error_code(),
            }
        }
    );
    let output = quote!(
        #entrypoint
        #probe_function
    );
    TokenStream::from(output)
}
