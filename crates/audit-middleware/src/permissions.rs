use std::collections::{HashMap, HashSet};

/// What a principal may do with the audit subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Emit audit events (record).
    Emit,
    /// Run queries over recorded logs.
    Query,
    /// Administrative operations: schema changes, DLQ redrive, retention runs.
    Administer,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Role(pub String);

impl Role {
    pub fn new(name: impl Into<String>) -> Self {
        Role(name.into())
    }
}

/// Role -> allowed actions. `default_allow` decides what unknown roles get,
/// so the policy can run as an allowlist (false) or a denylist (true).
#[derive(Debug, Clone)]
pub struct PermissionPolicy {
    grants: HashMap<Role, HashSet<Action>>,
    default_allow: bool,
}

impl PermissionPolicy {
    /// Everything allowed for everyone (opt-in security).
    pub fn allow_all() -> Self {
        Self {
            grants: HashMap::new(),
            default_allow: true,
        }
    }

    /// Nothing allowed unless granted.
    pub fn deny_by_default() -> Self {
        Self {
            grants: HashMap::new(),
            default_allow: false,
        }
    }

    pub fn grant(mut self, role: Role, actions: &[Action]) -> Self {
        self.grants
            .entry(role)
            .or_default()
            .extend(actions.iter().copied());
        self
    }

    pub fn is_allowed(&self, role: &Role, action: Action) -> bool {
        match self.grants.get(role) {
            Some(actions) => actions.contains(&action),
            None => self.default_allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_and_denylist() {
        let p = PermissionPolicy::deny_by_default()
            .grant(Role::new("auditor"), &[Action::Query])
            .grant(Role::new("service"), &[Action::Emit]);
        assert!(p.is_allowed(&Role::new("auditor"), Action::Query));
        assert!(!p.is_allowed(&Role::new("auditor"), Action::Emit));
        assert!(p.is_allowed(&Role::new("service"), Action::Emit));
        assert!(!p.is_allowed(&Role::new("intruder"), Action::Query));

        let open = PermissionPolicy::allow_all();
        assert!(open.is_allowed(&Role::new("anyone"), Action::Administer));
    }
}
