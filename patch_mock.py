import sys

with open("crates/mcpg-app/src/contract_tests.rs", "r") as f:
    content = f.read()

old_mock = """        fn create_launcher(&self, _ruleset: Option<OwnedFd>) -> Box<dyn CapsuleLauncher> {
            self.method_calls.lock().unwrap().push("create_launcher".into());
            Box::new(MockLauncher)
        }"""
new_mock = """        fn create_launcher(&self, _ruleset: Option<OwnedFd>) -> (Box<dyn CapsuleLauncher>, Option<RawFd>) {
            self.method_calls.lock().unwrap().push("create_launcher".into());
            (Box::new(MockLauncher), Some(42))
        }"""
content = content.replace(old_mock, new_mock)

old_assert = """assert!(pos_launcher < pos_observer, "launcher creation must be before starting observer thread");"""
new_assert = """assert!(pos_observer < pos_launcher, "observer thread must start before launcher creation");"""
content = content.replace(old_assert, new_assert)

with open("crates/mcpg-app/src/contract_tests.rs", "w") as f:
    f.write(content)
