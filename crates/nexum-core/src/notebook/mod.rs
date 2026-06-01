// Lifecycle-event mutation surface for notebook.git. Consumed by the
// promotion facade in a later change; the transitional dead_code allow is
// removed then.
#[allow(dead_code)]
pub(crate) mod lifecycle;
// Decision-record YAML emitter. Consumed by the lifecycle writer in a later
// change; the transitional dead_code allow is removed then.
#[allow(dead_code)]
pub(crate) mod emit;
