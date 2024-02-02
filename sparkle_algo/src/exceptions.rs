macro_rules! register_exception_names {
    ($($arg:ident),+) => {
        $(
            pub const $arg: &'static str = stringify!($arg);
        )+
    };
}

pub mod exception_names {
    register_exception_names!(
        AesGcmException,
        AggregationException,
        CommitmentException,
        ConfigException,
        HashException,
        HexToException,
        JsonToObjectException,
        ObjectToJsonException,
        PrefixException,
        SignatureException,
        SignUpException
    );
}
