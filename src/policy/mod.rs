//! Authorization. Token validation (authentication) lives in [`crate::auth`];
//! this module only answers "may this principal do this operation on this
//! server?" so that the static YAML policy can later be swapped for a policy
//! engine without touching transport code.
//!
//! ## Glob syntax
//!
//! Tool globs use [`globset`] with `/` treated as an ordinary character:
//! `*` matches any run of characters (including none), `?` matches exactly one
//! character, `[abc]` / `[a-z]` / `[!abc]` are character classes, and `{a,b}`
//! is alternation. Matching is case-sensitive. `"*"` matches every tool.
//!
//! Resolution is deterministic: deny rules are checked first across the
//! server-wide and per-user deny lists; if any matches the call is denied.
//! Otherwise the allow list is consulted; a per-user `allow` list *replaces*
//! the server-wide one. An empty effective allow list permits nothing.

use std::{collections::BTreeMap, sync::Arc};

use globset::{Glob, GlobBuilder, GlobMatcher};
use serde_json::Value;

use crate::config::{Config, Server, ToolRules, User};

/// An authenticated identity as seen by the policy layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Stable subject (`sub`). `anonymous` when auth is disabled.
    pub subject: String,
    /// Email if the token carried one.
    pub email: Option<String>,
    /// Name of the matching entry under `users`, if any.
    pub user: Option<String>,
    /// Scopes granted to the token (`scope` and `permissions` claims merged).
    pub scopes: Vec<String>,
    /// All token claims, for future argument-level policy.
    pub claims: serde_json::Map<String, Value>,
}

impl Principal {
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".into(),
            email: None,
            user: None,
            scopes: Vec::new(),
            claims: Default::default(),
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Everything a policy decision may consider.
#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    pub principal: &'a Principal,
    pub server: &'a str,
    pub method: &'a str,
    pub tool: Option<&'a str>,
    pub arguments: Option<&'a serde_json::Map<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { reason: String },
    Deny { reason: String },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
    pub fn allow(reason: impl Into<String>) -> Self {
        Decision::Allow { reason: reason.into() }
    }
    pub fn deny(reason: impl Into<String>) -> Self {
        Decision::Deny { reason: reason.into() }
    }
    pub fn reason(&self) -> &str {
        match self {
            Decision::Allow { reason } | Decision::Deny { reason } => reason,
        }
    }
}

/// The authorization interface. Implementations must be cheap to call on
/// every request and must never perform I/O.
pub trait Authorizer: Send + Sync + 'static {
    /// Decide whether the principal may perform the operation.
    fn authorize(&self, ctx: &RequestContext<'_>) -> Decision;

    /// Decide whether the principal may use the server at all (checked at the
    /// HTTP layer before any MCP message is parsed).
    fn authorize_server(&self, principal: &Principal, server: &str) -> Decision;

    /// Resolve a validated token's identity to a configured user name.
    fn resolve_user(&self, subject: &str, email: Option<&str>) -> Option<String>;
}

pub fn compile_glob(pattern: &str) -> Result<Glob, globset::Error> {
    GlobBuilder::new(pattern).literal_separator(false).case_insensitive(false).build()
}

#[derive(Debug, Clone)]
struct CompiledRules {
    allow: Vec<(String, GlobMatcher)>,
    deny: Vec<(String, GlobMatcher)>,
}

impl CompiledRules {
    fn compile(rules: &ToolRules) -> Self {
        let c = |v: &Vec<String>| {
            v.iter()
                .map(|g| (g.clone(), compile_glob(g).expect("validated at config load").compile_matcher()))
                .collect::<Vec<_>>()
        };
        Self { allow: c(&rules.allow), deny: c(&rules.deny) }
    }
    fn first_match<'s>(list: &'s [(String, GlobMatcher)], tool: &str) -> Option<&'s str> {
        list.iter().find(|(_, m)| m.is_match(tool)).map(|(g, _)| g.as_str())
    }
}

#[derive(Debug)]
struct ServerPolicy {
    allow_any_user: bool,
    allowed_users: Vec<String>,
    required_scopes: Vec<String>,
    tools: CompiledRules,
    user_tools: BTreeMap<String, CompiledRules>,
}

/// Static policy compiled from the YAML configuration.
#[derive(Debug)]
pub struct StaticPolicy {
    users: BTreeMap<String, User>,
    servers: BTreeMap<String, ServerPolicy>,
    auth_disabled: bool,
}

impl StaticPolicy {
    pub fn from_config(cfg: &Config) -> Arc<Self> {
        let servers = cfg
            .servers
            .iter()
            .map(|(name, s)| (name.clone(), Self::compile_server(s)))
            .collect();
        Arc::new(Self { users: cfg.users.clone(), servers, auth_disabled: cfg.auth.disabled })
    }

    fn compile_server(s: &Server) -> ServerPolicy {
        ServerPolicy {
            allow_any_user: s.allowed_users.iter().any(|u| u == "*"),
            allowed_users: s.allowed_users.iter().filter(|u| *u != "*").cloned().collect(),
            required_scopes: s.scopes.clone(),
            tools: CompiledRules::compile(&s.tools),
            user_tools: s.user_tools.iter().map(|(u, r)| (u.clone(), CompiledRules::compile(r))).collect(),
        }
    }

    fn tool_decision(&self, sp: &ServerPolicy, principal: &Principal, tool: &str) -> Decision {
        let user_rules = principal.user.as_deref().and_then(|u| sp.user_tools.get(u));
        if let Some(g) = CompiledRules::first_match(&sp.tools.deny, tool) {
            return Decision::deny(format!("tool `{tool}` matches server deny `{g}`"));
        }
        if let Some(ur) = user_rules
            && let Some(g) = CompiledRules::first_match(&ur.deny, tool)
        {
            return Decision::deny(format!("tool `{tool}` matches user deny `{g}`"));
        }
        let (allow, scope) = match user_rules {
            Some(ur) if !ur.allow.is_empty() => (&ur.allow, "user"),
            _ => (&sp.tools.allow, "server"),
        };
        match CompiledRules::first_match(allow, tool) {
            Some(g) => Decision::allow(format!("tool `{tool}` matches {scope} allow `{g}`")),
            None => Decision::deny(format!("tool `{tool}` matches no {scope} allow rule")),
        }
    }
}

impl Authorizer for StaticPolicy {
    fn resolve_user(&self, subject: &str, email: Option<&str>) -> Option<String> {
        // Subjects first (stable), then emails (convenience).
        if let Some((name, _)) = self.users.iter().find(|(_, u)| u.subjects.iter().any(|s| s == subject)) {
            return Some(name.clone());
        }
        let email = email?;
        self.users
            .iter()
            .find(|(_, u)| u.emails.iter().any(|e| e.eq_ignore_ascii_case(email)))
            .map(|(name, _)| name.clone())
    }

    fn authorize_server(&self, principal: &Principal, server: &str) -> Decision {
        let Some(sp) = self.servers.get(server) else {
            return Decision::deny(format!("unknown server `{server}`"));
        };
        if !self.auth_disabled {
            for s in &sp.required_scopes {
                if !principal.has_scope(s) {
                    return Decision::deny(format!("missing required scope `{s}`"));
                }
            }
        }
        if sp.allow_any_user {
            return Decision::allow("server allows any authenticated identity");
        }
        if self.auth_disabled && principal.user.is_none() {
            // Auth is off and the server does not admit "*": refuse rather than
            // silently granting the anonymous principal someone's access.
            return Decision::deny("auth disabled and server does not allow \"*\"");
        }
        match &principal.user {
            Some(u) if sp.allowed_users.iter().any(|a| a == u) => Decision::allow(format!("user `{u}` is in allowed_users")),
            Some(u) => Decision::deny(format!("user `{u}` is not in allowed_users")),
            None => Decision::deny(format!("subject `{}` does not map to a configured user", principal.subject)),
        }
    }

    fn authorize(&self, ctx: &RequestContext<'_>) -> Decision {
        let server_decision = self.authorize_server(ctx.principal, ctx.server);
        if !server_decision.is_allowed() {
            return server_decision;
        }
        let Some(sp) = self.servers.get(ctx.server) else {
            return Decision::deny(format!("unknown server `{}`", ctx.server));
        };
        match (ctx.method, ctx.tool) {
            ("tools/call", Some(tool)) => self.tool_decision(sp, ctx.principal, tool),
            ("tools/call", None) => Decision::deny("tools/call without a tool name"),
            // Discovery filtering reuses the tool decision.
            ("tools/list", Some(tool)) => self.tool_decision(sp, ctx.principal, tool),
            (method, _) => Decision::allow(format!("method `{method}` permitted for server-authorized users")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(yaml: &str) -> Arc<StaticPolicy> {
        let cfg = Config::parse(yaml).unwrap();
        StaticPolicy::from_config(&cfg)
    }

    const CFG: &str = r#"
public_url: https://mcp.example.com
auth:
  issuer: https://tenant.us.auth0.com/
users:
  brendan:
    subjects: ["google-oauth2|123"]
    emails: ["Brendan@Example.com"]
  guest:
    subjects: ["google-oauth2|999"]
servers:
  omg:
    command: omg-mcp
    allowed_users: [brendan, guest]
    tools:
      allow: ["*"]
      deny: ["admin.*", "docs_delete"]
    user_tools:
      guest:
        allow: ["docs_read", "docs_list", "query*"]
        deny: ["query_syntax"]
  toggl:
    command: toggl-mcp
    scopes: ["toggl:use"]
    allowed_users: ["*"]
    tools:
      allow: ["toggl_{get,list}_*"]
"#;

    fn principal(user: Option<&str>, scopes: &[&str]) -> Principal {
        Principal {
            subject: "google-oauth2|123".into(),
            email: None,
            user: user.map(Into::into),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            claims: Default::default(),
        }
    }

    fn call<'a>(p: &'a Principal, server: &'a str, tool: &'a str) -> RequestContext<'a> {
        RequestContext { principal: p, server, method: "tools/call", tool: Some(tool), arguments: None }
    }

    #[test]
    fn resolves_users_by_subject_then_email() {
        let p = policy(CFG);
        assert_eq!(p.resolve_user("google-oauth2|123", None).as_deref(), Some("brendan"));
        assert_eq!(p.resolve_user("auth0|zzz", Some("brendan@example.com")).as_deref(), Some("brendan"));
        assert_eq!(p.resolve_user("auth0|zzz", Some("nobody@example.com")), None);
    }

    #[test]
    fn deny_beats_allow_and_user_allow_replaces_server_allow() {
        let p = policy(CFG);
        let b = principal(Some("brendan"), &[]);
        assert!(p.authorize(&call(&b, "omg", "docs_read")).is_allowed());
        assert!(!p.authorize(&call(&b, "omg", "admin.reset")).is_allowed());
        assert!(!p.authorize(&call(&b, "omg", "docs_delete")).is_allowed());

        let g = principal(Some("guest"), &[]);
        assert!(p.authorize(&call(&g, "omg", "docs_read")).is_allowed());
        assert!(p.authorize(&call(&g, "omg", "query")).is_allowed());
        assert!(!p.authorize(&call(&g, "omg", "query_syntax")).is_allowed());
        assert!(!p.authorize(&call(&g, "omg", "docs_update")).is_allowed());
        assert!(!p.authorize(&call(&g, "omg", "docs_delete")).is_allowed());
    }

    #[test]
    fn server_level_checks() {
        let p = policy(CFG);
        let stranger = principal(None, &[]);
        assert!(!p.authorize_server(&stranger, "omg").is_allowed());
        assert!(!p.authorize_server(&stranger, "nope").is_allowed());
        // toggl admits anyone with the scope
        assert!(!p.authorize_server(&stranger, "toggl").is_allowed());
        let scoped = principal(None, &["toggl:use"]);
        assert!(p.authorize_server(&scoped, "toggl").is_allowed());
        assert!(p.authorize(&call(&scoped, "toggl", "toggl_list_projects")).is_allowed());
        assert!(!p.authorize(&call(&scoped, "toggl", "toggl_start_timer")).is_allowed());
    }

    #[test]
    fn non_tool_methods_follow_server_decision() {
        let p = policy(CFG);
        let b = principal(Some("brendan"), &[]);
        let ctx = RequestContext { principal: &b, server: "omg", method: "resources/list", tool: None, arguments: None };
        assert!(p.authorize(&ctx).is_allowed());
        let ctx = RequestContext { principal: &b, server: "omg", method: "tools/call", tool: None, arguments: None };
        assert!(!p.authorize(&ctx).is_allowed());
    }

    #[test]
    fn auth_disabled_requires_star() {
        let yaml = CFG.replace("  issuer: https://tenant.us.auth0.com/\n", "  disabled: true\n");
        let p = policy(&yaml);
        let anon = Principal::anonymous();
        assert!(!p.authorize_server(&anon, "omg").is_allowed());
        // required scopes are not enforced when auth is disabled
        assert!(p.authorize_server(&anon, "toggl").is_allowed());
    }
}
