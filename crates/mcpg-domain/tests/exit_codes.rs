use mcpg_domain::verdict::{combine, ExitCode};

#[test]
fn p1_exit_01_precedence_table() {
    let cases: Vec<(Vec<ExitCode>, ExitCode)> = vec![
        // Empty defaults to Pass (0)
        (vec![], ExitCode::Pass),
        // Single codes map to themselves
        (vec![ExitCode::Pass], ExitCode::Pass),
        (vec![ExitCode::FailSecurity], ExitCode::FailSecurity),
        (vec![ExitCode::FailFunctional], ExitCode::FailFunctional),
        (vec![ExitCode::Inconclusive], ExitCode::Inconclusive),
        (vec![ExitCode::Usage], ExitCode::Usage),
        (vec![ExitCode::UnsupportedHost], ExitCode::UnsupportedHost),
        (vec![ExitCode::Internal], ExitCode::Internal),
        // Precedence: 64 > 69 > 70 > 1 > 2 > 3 > 0
        // {Security, Inconclusive} -> 1
        (
            vec![ExitCode::FailSecurity, ExitCode::Inconclusive],
            ExitCode::FailSecurity,
        ),
        (
            vec![ExitCode::Inconclusive, ExitCode::FailSecurity],
            ExitCode::FailSecurity,
        ),
        // {Functional, Inconclusive} -> 2
        (
            vec![ExitCode::FailFunctional, ExitCode::Inconclusive],
            ExitCode::FailFunctional,
        ),
        // {Usage, Security} -> 64
        (
            vec![ExitCode::Usage, ExitCode::FailSecurity],
            ExitCode::Usage,
        ),
        // {Unsupported, Internal} -> 69
        (
            vec![ExitCode::UnsupportedHost, ExitCode::Internal],
            ExitCode::UnsupportedHost,
        ),
        // {Internal, Security} -> 70
        (
            vec![ExitCode::Internal, ExitCode::FailSecurity],
            ExitCode::Internal,
        ),
        // {Security, Functional} -> 1
        (
            vec![ExitCode::FailSecurity, ExitCode::FailFunctional],
            ExitCode::FailSecurity,
        ),
        // All together: Usage wins
        (
            vec![
                ExitCode::Pass,
                ExitCode::Inconclusive,
                ExitCode::FailFunctional,
                ExitCode::FailSecurity,
                ExitCode::Internal,
                ExitCode::UnsupportedHost,
                ExitCode::Usage,
            ],
            ExitCode::Usage,
        ),
    ];

    for (inputs, expected) in cases {
        let actual = combine(inputs.clone());
        assert_eq!(
            actual, expected,
            "combine({:?}) expected {:?}, got {:?}",
            inputs, expected, actual
        );
    }
}

#[test]
fn exit_code_as_i32() {
    assert_eq!(ExitCode::Pass.as_i32(), 0);
    assert_eq!(ExitCode::FailSecurity.as_i32(), 1);
    assert_eq!(ExitCode::FailFunctional.as_i32(), 2);
    assert_eq!(ExitCode::Inconclusive.as_i32(), 3);
    assert_eq!(ExitCode::Usage.as_i32(), 64);
    assert_eq!(ExitCode::UnsupportedHost.as_i32(), 69);
    assert_eq!(ExitCode::Internal.as_i32(), 70);
}
