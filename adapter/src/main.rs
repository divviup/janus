use async_trait::async_trait;
use janus_collector::Collection;
use prio::{
    codec::{Decode, Encode},
    vdaf::{
        prio3::{Prio3, Prio3Count, Prio3Histogram, Prio3Sum},
        Vdaf,
    },
};
use std::fmt::{Debug, Display};
use std::hash::Hash;

#[derive(Debug, thiserror::Error)]
pub enum Error {}

#[async_trait]
pub trait EmitterBackend {
    async fn emit_prio3count(
        &self,
        collection: Collection<<Prio3Count as Vdaf>::AggregateResult, QueryType>,
    ) -> Result<(), Error>;
}

// struct FileEmitterBackend {}

// #[async_trait]
// impl EmitterBackend<u64, FixedSize> for FileEmitterBackend {
//     async fn emit(&self, collection: Collection<u64, FixedSize>) -> Result<(), Error> {
//         todo!()
//     }
// }

#[tokio::main]
async fn main() {
    // let backend = FileEmitterBackend {};
    // let collection: Collection<<Prio3Count as Vdaf>::AggregateResult, FixedSize> =
    //     Collection::new(todo!(), todo!(), todo!(), todo!());
    // backend.emit(collection).await.unwrap()
}

// use janus_collector::{AuthenticationToken, Collection, Collector};
// use janus_core::test_util::dummy_vdaf;
// use janus_messages::{
//     query_type::{FixedSize, QueryType},
//     FixedSizeQuery, HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId, Query,
// };
// use prio::vdaf::{
//     self,
//     prio3::{Prio3Count, Prio3Histogram, Prio3Sum},
//     Vdaf,
// };
// use rand::random;
// use std::{env, sync::Arc};
// use tokio::task::JoinHandle;
// use url::Url;

// /// do something with aggregate results
// pub trait Adapter<T, Q: QueryType> {
//     fn handle(&self, result: Collection<T, Q>) -> Result<(), Error>;
// }

// pub struct OtelAdapter {}

// impl OtelAdapter {
//     pub fn new() -> Self {
//         Self {}
//     }
// }

// impl<Q: QueryType> Adapter<u64, Q> for OtelAdapter {
//     fn handle(&self, result: Collection<u64, Q>) -> Result<(), Error> {
//         println!("OtelAdapter as Adapter<Prio3Count, FixedSize>");
//         dbg!(result);
//         Ok(())
//     }
// }

// impl<Q: QueryType> Adapter<Prio3Sum, Q> for OtelAdapter {
//     fn handle(
//         &self,
//         result: Collection<<Prio3Sum as Vdaf>::AggregateResult, Q>,
//     ) -> Result<(), Error> {
//         println!("OtelAdapter as Adapter<Prio3Sum, FixedSize>");
//         dbg!(result);
//         Ok(())
//     }
// }

// impl<Q: QueryType> Adapter<Prio3Histogram, Q> for OtelAdapter {
//     fn handle(
//         &self,
//         result: Collection<<Prio3Histogram as Vdaf>::AggregateResult, Q>,
//     ) -> Result<(), Error> {
//         println!("OtelAdapter as Adapter<Prio3Histogram, FixedSize>");
//         dbg!(result);
//         Ok(())
//     }
// }

// impl<Q: QueryType> Adapter<dummy_vdaf::Vdaf, Q> for OtelAdapter {
//     fn handle(
//         &self,
//         result: Collection<<dummy_vdaf::Vdaf as Vdaf>::AggregateResult, Q>,
//     ) -> Result<(), Error> {
//         println!("OtelAdapter as Adapter<dummy_vdaf::Vdaf, FixedSize>");
//         dbg!(result);
//         Ok(())
//     }
// }

// pub struct AggregateEmitter<V, Q>
// where
//     V: vdaf::Collector + Send + Sync + 'static,
//     <V as Vdaf>::AggregationParam: Send + Sync + 'static,
//     Q: QueryType,
// {
//     adapter: Arc<dyn Adapter<V, Q> + Send + Sync>,
//     collector: Collector<V>,
//     aggregation_param: V::AggregationParam,
// }

// impl<V, Q> AggregateEmitter<V, Q>
// where
//     V: vdaf::Collector + Send + Sync + 'static,
//     <V as Vdaf>::AggregationParam: Send + Sync + 'static,
//     Q: QueryType,
// {
//     pub fn new(
//         adapter: Arc<dyn Adapter<V, Q> + Send + Sync>,
//         collector: Collector<V>,
//         aggregation_param: V::AggregationParam,
//     ) -> Self {
//         Self {
//             adapter,
//             collector,
//             aggregation_param,
//         }
//     }

//     pub async fn spawn(self, query: Q::QueryBody) -> JoinHandle<Result<(), Error>> {
//         tokio::spawn(async move {
//             loop {
//                 let result = self
//                     .collector
//                     .collect(Query::new(query.clone()), &self.aggregation_param)
//                     .await
//                     .unwrap();

//                 self.adapter.handle(result).unwrap();

//                 // sleep
//             }
//         })
//     }
// }

// impl<V> AggregateEmitter<V, FixedSize>
// where
//     V: vdaf::Collector + Send + Sync + 'static,
//     <V as Vdaf>::AggregationParam: Send + Sync + 'static,
// {
//     pub fn new_fixed_size(
//         adapter: Arc<dyn Adapter<V, FixedSize> + Send + Sync>,
//         collector: Collector<V>,
//         aggregation_param: V::AggregationParam,
//     ) -> Self {
//         Self {
//             adapter,
//             collector,
//             aggregation_param,
//         }
//     }
// }

// #[tokio::main]
// async fn main() {
//     let vdaf = Prio3Count::new_count(2).unwrap();
//     let task_id = random();

//     let hpke_keypair = janus_core::hpke::generate_hpke_config_and_private_key(
//         HpkeConfigId::from(0),
//         HpkeKemId::X25519HkdfSha256,
//         HpkeKdfId::HkdfSha256,
//         HpkeAeadId::Aes128Gcm,
//     )
//     .unwrap();

//     let collector = Collector::new(
//         task_id,
//         Url::parse("").unwrap(),
//         AuthenticationToken::new_bearer_token_from_string(
//             env::var("COLLECTOR_AUTH_TOKEN").unwrap(),
//         )
//         .unwrap(),
//         hpke_keypair,
//         vdaf,
//     )
//     .unwrap();

//     let adapter = Arc::new(OtelAdapter::new());
//     AggregateEmitter::new_fixed_size(adapter.clone(), collector, ())
//         .spawn(FixedSizeQuery::CurrentBatch)
//         .await;

//     println!("Hello, world!");
// }
