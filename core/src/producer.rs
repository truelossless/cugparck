use cubecl::{client::ComputeClient, Runtime};

pub struct Producer<Backend: Runtime> {
    pub number: u8,
    pub client: ComputeClient<Backend::Server, Backend::Channel>,
}

impl<Backend: Runtime> Producer<Backend> {
    pub fn new(number: u8) -> Self {
        Self {
            number,
            client: Backend::client(&Default::default()),
        }
    }
}
