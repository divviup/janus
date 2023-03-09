//! Implements portions of aggregation job continuation for the helper.

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use http::{header::CONTENT_TYPE, StatusCode};
    use hyper::body;
    use janus_aggregator_core::task::Task;
    use janus_messages::{AggregationJobContinueReq, AggregationJobId, AggregationJobResp};
    use prio::codec::{Decode, Encode};
    use serde_json::json;
    use warp::{filters::BoxedFilter, reply::Response, Reply};

    async fn post_aggregation_job(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        filter: &BoxedFilter<(impl Reply + 'static,)>,
    ) -> Response {
        warp::test::request()
            .method("POST")
            .path(task.aggregation_job_uri(aggregation_job_id).unwrap().path())
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregationJobContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(filter)
            .await
            .unwrap()
            .into_response()
    }

    pub async fn post_aggregation_job_and_decode(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        filter: &BoxedFilter<(impl Reply + 'static,)>,
    ) -> AggregationJobResp {
        let mut response = post_aggregation_job(task, aggregation_job_id, request, filter).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregationJobResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(response.body_mut()).await.unwrap();
        AggregationJobResp::get_decoded(&body_bytes).unwrap()
    }

    pub async fn post_aggregation_job_expecting_error(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        filter: &BoxedFilter<(impl Reply + 'static,)>,
        want_status: StatusCode,
        want_error_type: &str,
        want_error_title: &str,
    ) {
        let (parts, body) = post_aggregation_job(task, aggregation_job_id, request, filter)
            .await
            .into_parts();

        assert_eq!(want_status, parts.status);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
                "type": want_error_type,
                "title": want_error_title,
                "taskid": format!("{}", task.id()),
            })
        );
    }
}
