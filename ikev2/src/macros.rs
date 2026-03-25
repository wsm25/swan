macro_rules! const_variant {
    ($type:ty: $($const_name:ident = $value:expr;)*) => {
        $(
            pub const $const_name: $type = $value;
        )*
    };
    ($mapname:ident, $type:ty, $infotype:ty: $(($const_name:ident, $value:expr, $info:expr),)*) => {
        $(
            pub const $const_name: $type = $value;
        )*

        pub static $mapname: ::phf::Map<$type, $infotype> = ::phf::phf_map! {
            $(
                $value => $info,
            )*
        };
    };
}
