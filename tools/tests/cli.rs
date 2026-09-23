use trycmd::TestCases;

#[test]
fn cli_tests() {
    let test_cases = TestCases::new();

    test_cases.case("tests/cmd/dap_decode.trycmd");
    test_cases.case("tests/cmd/hpke_keygen.trycmd");

    cfg_select! {
        feature = "fpvec_bounded_l2" => {
            test_cases.case("tests/cmd/collect_fpvec_bounded_l2.trycmd");
        }
        _ => {
            test_cases.case("tests/cmd/collect.trycmd");
        }
    }

    test_cases.run();
}
