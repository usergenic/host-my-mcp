//! The three pages a human sees: provider picker, consent, and errors.

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};

use super::util::html_escape as esc;

const STYLE: &str = r#"
:root{color-scheme:light dark;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
body{margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;background:Canvas;color:CanvasText}
main{max-width:30rem;width:100%;padding:2rem;box-sizing:border-box}
h1{font-size:1.25rem;margin:0 0 1rem}
p{line-height:1.5;margin:.5rem 0}
.muted{opacity:.7;font-size:.9rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;word-break:break-all}
ul{padding-left:1.2rem}
.actions{display:flex;gap:.75rem;margin-top:1.5rem}
button,a.button{font:inherit;padding:.6rem 1.1rem;border-radius:.5rem;border:1px solid currentColor;background:transparent;color:inherit;cursor:pointer;text-decoration:none;display:inline-block}
button.primary{background:CanvasText;color:Canvas;border-color:CanvasText}
.card{border:1px solid color-mix(in srgb,currentColor 25%,transparent);border-radius:.75rem;padding:1rem 1.25rem;margin:.75rem 0}
"#;

pub fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>{} · host-my-mcp</title><style>{STYLE}</style></head><body><main>{body}<p class=\"muted\" style=\"margin-top:2rem\">host-my-mcp</p></main></body></html>",
        esc(title)
    );
    let mut resp = (status, Html(html)).into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

/// A terminal error. `return_to` is an optional (url, label) link that sends
/// the user back to the client with the matching OAuth error.
pub fn error_page(
    status: StatusCode,
    title: &str,
    message: &str,
    details: &[(&str, &str)],
    return_to: Option<(&str, &str)>,
) -> Response {
    let mut body = format!("<h1>{}</h1><p>{}</p>", esc(title), esc(message));
    if !details.is_empty() {
        body.push_str("<div class=\"card\">");
        for (k, v) in details {
            body.push_str(&format!(
                "<p class=\"muted\">{}</p><p><code>{}</code></p>",
                esc(k),
                esc(v)
            ));
        }
        body.push_str("</div>");
    }
    if let Some((url, label)) = return_to {
        body.push_str(&format!(
            "<div class=\"actions\"><a class=\"button\" href=\"{}\">{}</a></div>",
            esc(url),
            esc(label)
        ));
    }
    page(status, title, &body)
}

pub struct ConsentView<'a> {
    pub txn: &'a str,
    pub client_name: &'a str,
    pub client_uri: Option<&'a str>,
    pub redirect_uri: &'a str,
    pub servers: &'a [String],
    pub scopes: &'a [String],
    pub identity_label: &'a str,
    pub action_url: &'a str,
}

pub fn consent_page(v: &ConsentView<'_>) -> Response {
    let mut body = format!(
        "<h1>Allow {} to use your MCP servers?</h1>",
        esc(v.client_name)
    );
    body.push_str(&format!(
        "<p>You are signed in as <strong>{}</strong>.</p>",
        esc(v.identity_label)
    ));
    body.push_str("<div class=\"card\"><p class=\"muted\">This application</p>");
    body.push_str(&format!("<p>{}</p>", esc(v.client_name)));
    if let Some(u) = v.client_uri {
        body.push_str(&format!("<p><code>{}</code></p>", esc(u)));
    }
    body.push_str(&format!(
        "<p class=\"muted\">will receive tokens at</p><p><code>{}</code></p>",
        esc(v.redirect_uri)
    ));
    body.push_str("<p class=\"muted\">and may call</p><ul>");
    for s in v.servers {
        body.push_str(&format!("<li><code>{}</code></li>", esc(s)));
    }
    body.push_str("</ul>");
    if !v.scopes.is_empty() {
        body.push_str(&format!(
            "<p class=\"muted\">with scopes <code>{}</code></p>",
            esc(&v.scopes.join(" "))
        ));
    }
    body.push_str("</div>");
    body.push_str("<p class=\"muted\">Only approve if you started this connection yourself. Your choice is remembered for this application.</p>");
    body.push_str(&format!(
        "<form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"txn\" value=\"{}\"><div class=\"actions\"><button class=\"primary\" type=\"submit\" name=\"action\" value=\"approve\">Allow</button><button type=\"submit\" name=\"action\" value=\"deny\">Cancel</button></div></form>",
        esc(v.action_url),
        esc(v.txn)
    ));
    page(StatusCode::OK, "Allow access", &body)
}

/// `providers` = (link href, label).
pub fn picker_page(client_name: &str, providers: &[(String, String)]) -> Response {
    let mut body = format!(
        "<h1>Sign in to continue to {}</h1><p>Choose how to sign in:</p><div class=\"actions\" style=\"flex-wrap:wrap\">",
        esc(client_name)
    );
    for (href, label) in providers {
        body.push_str(&format!(
            "<a class=\"button\" href=\"{}\">Continue with {}</a>",
            esc(href),
            esc(label)
        ));
    }
    body.push_str("</div>");
    page(StatusCode::OK, "Sign in", &body)
}
