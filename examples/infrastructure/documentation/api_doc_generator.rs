//! API Documentation Generator
//!
//! This example demonstrates automatic API documentation generation
//! for Rust projects, including OpenAPI/Swagger spec generation,
//! rustdoc integration, and markdown documentation output.

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// OpenAPI Types
// ============================================================================

/// OpenAPI specification version
#[derive(Debug, Clone, Copy)]
pub enum OpenApiVersion {
    V3_0,
    V3_1,
}

impl OpenApiVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            OpenApiVersion::V3_0 => "3.0.3",
            OpenApiVersion::V3_1 => "3.1.0",
        }
    }
}

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Patch => "patch",
            HttpMethod::Delete => "delete",
            HttpMethod::Head => "head",
            HttpMethod::Options => "options",
        }
    }
}

/// JSON Schema types
#[derive(Debug, Clone)]
pub enum SchemaType {
    String,
    Integer,
    Number,
    Boolean,
    Array(Box<SchemaType>),
    Object(HashMap<String, PropertySchema>),
    Ref(String),
    OneOf(Vec<SchemaType>),
    AnyOf(Vec<SchemaType>),
    Null,
}

impl SchemaType {
    pub fn as_json_type(&self) -> &str {
        match self {
            SchemaType::String => "string",
            SchemaType::Integer => "integer",
            SchemaType::Number => "number",
            SchemaType::Boolean => "boolean",
            SchemaType::Array(_) => "array",
            SchemaType::Object(_) => "object",
            SchemaType::Ref(_) => "$ref",
            SchemaType::OneOf(_) => "oneOf",
            SchemaType::AnyOf(_) => "anyOf",
            SchemaType::Null => "null",
        }
    }
}

/// Property schema
#[derive(Debug, Clone)]
pub struct PropertySchema {
    pub schema_type: SchemaType,
    pub description: Option<String>,
    pub required: bool,
    pub nullable: bool,
    pub example: Option<String>,
    pub default: Option<String>,
    pub format: Option<String>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub enum_values: Option<Vec<String>>,
}

impl PropertySchema {
    pub fn new(schema_type: SchemaType) -> Self {
        Self {
            schema_type,
            description: None,
            required: false,
            nullable: false,
            example: None,
            default: None,
            format: None,
            minimum: None,
            maximum: None,
            min_length: None,
            max_length: None,
            pattern: None,
            enum_values: None,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    pub fn example(mut self, example: &str) -> Self {
        self.example = Some(example.to_string());
        self
    }

    pub fn format(mut self, format: &str) -> Self {
        self.format = Some(format.to_string());
        self
    }
}

// ============================================================================
// OpenAPI Specification Builder
// ============================================================================

/// OpenAPI info object
#[derive(Debug, Clone)]
pub struct ApiInfo {
    pub title: String,
    pub description: Option<String>,
    pub version: String,
    pub terms_of_service: Option<String>,
    pub contact: Option<Contact>,
    pub license: Option<License>,
}

/// Contact information
#[derive(Debug, Clone)]
pub struct Contact {
    pub name: Option<String>,
    pub url: Option<String>,
    pub email: Option<String>,
}

/// License information
#[derive(Debug, Clone)]
pub struct License {
    pub name: String,
    pub url: Option<String>,
}

/// Server definition
#[derive(Debug, Clone)]
pub struct Server {
    pub url: String,
    pub description: Option<String>,
    pub variables: HashMap<String, ServerVariable>,
}

/// Server variable
#[derive(Debug, Clone)]
pub struct ServerVariable {
    pub default: String,
    pub description: Option<String>,
    pub enum_values: Option<Vec<String>>,
}

/// API endpoint/operation
#[derive(Debug, Clone)]
pub struct Operation {
    pub operation_id: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<RequestBody>,
    pub responses: HashMap<String, Response>,
    pub security: Vec<HashMap<String, Vec<String>>>,
    pub deprecated: bool,
}

/// Parameter location
#[derive(Debug, Clone, Copy)]
pub enum ParameterIn {
    Query,
    Path,
    Header,
    Cookie,
}

impl ParameterIn {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParameterIn::Query => "query",
            ParameterIn::Path => "path",
            ParameterIn::Header => "header",
            ParameterIn::Cookie => "cookie",
        }
    }
}

/// API parameter
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub location: ParameterIn,
    pub description: Option<String>,
    pub required: bool,
    pub deprecated: bool,
    pub schema: PropertySchema,
}

/// Request body
#[derive(Debug, Clone)]
pub struct RequestBody {
    pub description: Option<String>,
    pub required: bool,
    pub content: HashMap<String, MediaType>,
}

/// Media type content
#[derive(Debug, Clone)]
pub struct MediaType {
    pub schema: PropertySchema,
    pub example: Option<String>,
}

/// API response
#[derive(Debug, Clone)]
pub struct Response {
    pub description: String,
    pub content: HashMap<String, MediaType>,
    pub headers: HashMap<String, PropertySchema>,
}

/// Security scheme
#[derive(Debug, Clone)]
pub enum SecurityScheme {
    ApiKey {
        name: String,
        location: ParameterIn,
    },
    Http {
        scheme: String,
        bearer_format: Option<String>,
    },
    OAuth2 {
        flows: OAuth2Flows,
    },
    OpenIdConnect {
        openid_connect_url: String,
    },
}

/// OAuth2 flows
#[derive(Debug, Clone, Default)]
pub struct OAuth2Flows {
    pub authorization_code: Option<OAuth2Flow>,
    pub implicit: Option<OAuth2Flow>,
    pub password: Option<OAuth2Flow>,
    pub client_credentials: Option<OAuth2Flow>,
}

/// OAuth2 flow
#[derive(Debug, Clone)]
pub struct OAuth2Flow {
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub refresh_url: Option<String>,
    pub scopes: HashMap<String, String>,
}

/// Tag for grouping operations
#[derive(Debug, Clone)]
pub struct Tag {
    pub name: String,
    pub description: Option<String>,
    pub external_docs: Option<ExternalDocs>,
}

/// External documentation
#[derive(Debug, Clone)]
pub struct ExternalDocs {
    pub url: String,
    pub description: Option<String>,
}

// ============================================================================
// OpenAPI Spec Builder
// ============================================================================

/// OpenAPI specification builder
pub struct OpenApiBuilder {
    version: OpenApiVersion,
    info: ApiInfo,
    servers: Vec<Server>,
    paths: HashMap<String, HashMap<HttpMethod, Operation>>,
    components: Components,
    tags: Vec<Tag>,
    external_docs: Option<ExternalDocs>,
}

/// Components container
#[derive(Default)]
pub struct Components {
    pub schemas: HashMap<String, PropertySchema>,
    pub security_schemes: HashMap<String, SecurityScheme>,
    pub parameters: HashMap<String, Parameter>,
    pub responses: HashMap<String, Response>,
    pub request_bodies: HashMap<String, RequestBody>,
}

impl OpenApiBuilder {
    pub fn new(title: &str, version: &str) -> Self {
        Self {
            version: OpenApiVersion::V3_0,
            info: ApiInfo {
                title: title.to_string(),
                description: None,
                version: version.to_string(),
                terms_of_service: None,
                contact: None,
                license: None,
            },
            servers: Vec::new(),
            paths: HashMap::new(),
            components: Components::default(),
            tags: Vec::new(),
            external_docs: None,
        }
    }

    pub fn openapi_version(mut self, version: OpenApiVersion) -> Self {
        self.version = version;
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.info.description = Some(desc.to_string());
        self
    }

    pub fn contact(mut self, name: &str, email: &str, url: Option<&str>) -> Self {
        self.info.contact = Some(Contact {
            name: Some(name.to_string()),
            email: Some(email.to_string()),
            url: url.map(String::from),
        });
        self
    }

    pub fn license(mut self, name: &str, url: Option<&str>) -> Self {
        self.info.license = Some(License {
            name: name.to_string(),
            url: url.map(String::from),
        });
        self
    }

    pub fn server(mut self, url: &str, description: Option<&str>) -> Self {
        self.servers.push(Server {
            url: url.to_string(),
            description: description.map(String::from),
            variables: HashMap::new(),
        });
        self
    }

    pub fn tag(mut self, name: &str, description: Option<&str>) -> Self {
        self.tags.push(Tag {
            name: name.to_string(),
            description: description.map(String::from),
            external_docs: None,
        });
        self
    }

    pub fn path(mut self, path: &str, method: HttpMethod, operation: Operation) -> Self {
        self.paths
            .entry(path.to_string())
            .or_default()
            .insert(method, operation);
        self
    }

    pub fn schema(mut self, name: &str, schema: PropertySchema) -> Self {
        self.components.schemas.insert(name.to_string(), schema);
        self
    }

    pub fn security_scheme(mut self, name: &str, scheme: SecurityScheme) -> Self {
        self.components
            .security_schemes
            .insert(name.to_string(), scheme);
        self
    }

    /// Generate OpenAPI JSON
    pub fn to_json(&self) -> String {
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str(&format!("  \"openapi\": \"{}\",\n", self.version.as_str()));

        // Info
        json.push_str("  \"info\": {\n");
        json.push_str(&format!("    \"title\": \"{}\",\n", self.info.title));
        json.push_str(&format!("    \"version\": \"{}\"\n", self.info.version));
        if let Some(desc) = &self.info.description {
            json = json.replace(
                "\n  \"info\"",
                &format!(",\n    \"description\": \"{}\"\n  \"info\"", desc),
            );
        }
        json.push_str("  },\n");

        // Servers
        if !self.servers.is_empty() {
            json.push_str("  \"servers\": [\n");
            for (i, server) in self.servers.iter().enumerate() {
                json.push_str("    {\n");
                json.push_str(&format!("      \"url\": \"{}\"", server.url));
                if let Some(desc) = &server.description {
                    json.push_str(&format!(",\n      \"description\": \"{}\"", desc));
                }
                json.push_str("\n    }");
                if i < self.servers.len() - 1 {
                    json.push(',');
                }
                json.push('\n');
            }
            json.push_str("  ],\n");
        }

        // Paths
        json.push_str("  \"paths\": {\n");
        let path_count = self.paths.len();
        for (i, (path, methods)) in self.paths.iter().enumerate() {
            json.push_str(&format!("    \"{}\": {{\n", path));

            let method_count = methods.len();
            for (j, (method, op)) in methods.iter().enumerate() {
                json.push_str(&format!("      \"{}\": {{\n", method.as_str()));
                json.push_str(&format!("        \"operationId\": \"{}\"", op.operation_id));

                if let Some(summary) = &op.summary {
                    json.push_str(&format!(",\n        \"summary\": \"{}\"", summary));
                }

                if !op.tags.is_empty() {
                    json.push_str(&format!(
                        ",\n        \"tags\": [{}]",
                        op.tags
                            .iter()
                            .map(|t| format!("\"{}\"", t))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                // Parameters
                if !op.parameters.is_empty() {
                    json.push_str(",\n        \"parameters\": [\n");
                    for (k, param) in op.parameters.iter().enumerate() {
                        json.push_str("          {\n");
                        json.push_str(&format!("            \"name\": \"{}\",\n", param.name));
                        json.push_str(&format!(
                            "            \"in\": \"{}\",\n",
                            param.location.as_str()
                        ));
                        json.push_str(&format!("            \"required\": {},\n", param.required));
                        json.push_str(&format!(
                            "            \"schema\": {{ \"type\": \"{}\" }}\n",
                            param.schema.schema_type.as_json_type()
                        ));
                        json.push_str("          }");
                        if k < op.parameters.len() - 1 {
                            json.push(',');
                        }
                        json.push('\n');
                    }
                    json.push_str("        ]");
                }

                // Responses
                json.push_str(",\n        \"responses\": {\n");
                let resp_count = op.responses.len();
                for (k, (code, resp)) in op.responses.iter().enumerate() {
                    json.push_str(&format!("          \"{}\": {{\n", code));
                    json.push_str(&format!(
                        "            \"description\": \"{}\"\n",
                        resp.description
                    ));
                    json.push_str("          }");
                    if k < resp_count - 1 {
                        json.push(',');
                    }
                    json.push('\n');
                }
                json.push_str("        }\n");

                json.push_str("      }");
                if j < method_count - 1 {
                    json.push(',');
                }
                json.push('\n');
            }

            json.push_str("    }");
            if i < path_count - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        json.push_str("  }\n");

        json.push_str("}\n");
        json
    }

    /// Generate OpenAPI YAML
    pub fn to_yaml(&self) -> String {
        let mut yaml = String::new();
        yaml.push_str(&format!("openapi: '{}'\n", self.version.as_str()));

        yaml.push_str("info:\n");
        yaml.push_str(&format!("  title: '{}'\n", self.info.title));
        yaml.push_str(&format!("  version: '{}'\n", self.info.version));
        if let Some(desc) = &self.info.description {
            yaml.push_str(&format!("  description: '{}'\n", desc));
        }

        if !self.servers.is_empty() {
            yaml.push_str("servers:\n");
            for server in &self.servers {
                yaml.push_str(&format!("  - url: '{}'\n", server.url));
                if let Some(desc) = &server.description {
                    yaml.push_str(&format!("    description: '{}'\n", desc));
                }
            }
        }

        yaml.push_str("paths:\n");
        for (path, methods) in &self.paths {
            yaml.push_str(&format!("  '{}':\n", path));
            for (method, op) in methods {
                yaml.push_str(&format!("    {}:\n", method.as_str()));
                yaml.push_str(&format!("      operationId: {}\n", op.operation_id));
                if let Some(summary) = &op.summary {
                    yaml.push_str(&format!("      summary: '{}'\n", summary));
                }
                if !op.tags.is_empty() {
                    yaml.push_str("      tags:\n");
                    for tag in &op.tags {
                        yaml.push_str(&format!("        - {}\n", tag));
                    }
                }
                yaml.push_str("      responses:\n");
                for (code, resp) in &op.responses {
                    yaml.push_str(&format!("        '{}':\n", code));
                    yaml.push_str(&format!("          description: '{}'\n", resp.description));
                }
            }
        }

        yaml
    }
}

// ============================================================================
// Rust Doc Parser
// ============================================================================

/// Documentation item
#[derive(Debug, Clone)]
pub struct DocItem {
    pub name: String,
    pub kind: DocItemKind,
    pub visibility: Visibility,
    pub doc_comment: Option<String>,
    pub signature: String,
    pub examples: Vec<String>,
    pub attributes: Vec<String>,
    pub children: Vec<DocItem>,
}

/// Item kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocItemKind {
    Module,
    Struct,
    Enum,
    Trait,
    Function,
    Method,
    Constant,
    Static,
    TypeAlias,
    Macro,
    Impl,
}

impl DocItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DocItemKind::Module => "mod",
            DocItemKind::Struct => "struct",
            DocItemKind::Enum => "enum",
            DocItemKind::Trait => "trait",
            DocItemKind::Function => "fn",
            DocItemKind::Method => "method",
            DocItemKind::Constant => "const",
            DocItemKind::Static => "static",
            DocItemKind::TypeAlias => "type",
            DocItemKind::Macro => "macro",
            DocItemKind::Impl => "impl",
        }
    }
}

/// Visibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Crate,
    Super,
    Private,
}

/// Documentation generator
pub struct DocGenerator {
    items: Vec<DocItem>,
    crate_name: String,
    version: String,
}

impl DocGenerator {
    pub fn new(crate_name: &str, version: &str) -> Self {
        Self {
            items: Vec::new(),
            crate_name: crate_name.to_string(),
            version: version.to_string(),
        }
    }

    pub fn add_item(&mut self, item: DocItem) {
        self.items.push(item);
    }

    /// Generate markdown documentation
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# {} v{}\n\n", self.crate_name, self.version));

        // Table of contents
        md.push_str("## Table of Contents\n\n");
        for item in &self.items {
            if item.visibility == Visibility::Public {
                md.push_str(&format!(
                    "- [{}](#{})\n",
                    item.name,
                    item.name.to_lowercase()
                ));
            }
        }
        md.push('\n');

        // Items
        for item in &self.items {
            if item.visibility != Visibility::Public {
                continue;
            }

            md.push_str(&format!("## {}\n\n", item.name));
            md.push_str(&format!("`{} {}`\n\n", item.kind.as_str(), item.signature));

            if let Some(doc) = &item.doc_comment {
                md.push_str(doc);
                md.push_str("\n\n");
            }

            if !item.examples.is_empty() {
                md.push_str("### Examples\n\n");
                for example in &item.examples {
                    md.push_str("```rust\n");
                    md.push_str(example);
                    md.push_str("\n```\n\n");
                }
            }

            if !item.children.is_empty() {
                md.push_str("### Members\n\n");
                for child in &item.children {
                    md.push_str(&format!(
                        "- `{}` - {}\n",
                        child.signature,
                        child.doc_comment.as_deref().unwrap_or("")
                    ));
                }
                md.push('\n');
            }
        }

        md
    }

    /// Generate HTML documentation
    pub fn to_html(&self) -> String {
        let mut html = String::from(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{crate_name} Documentation</title>
    <style>
        body { font-family: sans-serif; margin: 0; padding: 20px; }
        .sidebar { position: fixed; left: 0; top: 0; width: 250px; height: 100%; background: #f5f5f5; padding: 20px; }
        .content { margin-left: 290px; }
        .item { margin-bottom: 30px; }
        .signature { background: #f0f0f0; padding: 10px; border-radius: 4px; font-family: monospace; }
        h1 { color: #333; }
        h2 { border-bottom: 2px solid #ddd; padding-bottom: 5px; }
        code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
        pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
"#,
        );

        html = html.replace("{crate_name}", &self.crate_name);

        // Sidebar
        html.push_str("<div class=\"sidebar\">\n");
        html.push_str(&format!("<h2>{}</h2>\n", self.crate_name));
        html.push_str("<ul>\n");
        for item in &self.items {
            if item.visibility == Visibility::Public {
                html.push_str(&format!(
                    "  <li><a href=\"#{}\">{}</a></li>\n",
                    item.name.to_lowercase(),
                    item.name
                ));
            }
        }
        html.push_str("</ul>\n</div>\n");

        // Content
        html.push_str("<div class=\"content\">\n");
        html.push_str(&format!("<h1>{} v{}</h1>\n", self.crate_name, self.version));

        for item in &self.items {
            if item.visibility != Visibility::Public {
                continue;
            }

            html.push_str(&format!(
                "<div class=\"item\" id=\"{}\">\n",
                item.name.to_lowercase()
            ));
            html.push_str(&format!("<h2>{}</h2>\n", item.name));
            html.push_str(&format!(
                "<div class=\"signature\"><code>{} {}</code></div>\n",
                item.kind.as_str(),
                escape_html(&item.signature)
            ));

            if let Some(doc) = &item.doc_comment {
                html.push_str(&format!("<p>{}</p>\n", escape_html(doc)));
            }

            if !item.examples.is_empty() {
                html.push_str("<h3>Examples</h3>\n");
                for example in &item.examples {
                    html.push_str("<pre><code>");
                    html.push_str(&escape_html(example));
                    html.push_str("</code></pre>\n");
                }
            }

            html.push_str("</div>\n");
        }

        html.push_str("</div>\n</body>\n</html>");
        html
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ============================================================================
// Operation Builder
// ============================================================================

/// Fluent API for building operations
pub struct OperationBuilder {
    operation: Operation,
}

impl OperationBuilder {
    pub fn new(operation_id: &str) -> Self {
        Self {
            operation: Operation {
                operation_id: operation_id.to_string(),
                summary: None,
                description: None,
                tags: Vec::new(),
                parameters: Vec::new(),
                request_body: None,
                responses: HashMap::new(),
                security: Vec::new(),
                deprecated: false,
            },
        }
    }

    pub fn summary(mut self, summary: &str) -> Self {
        self.operation.summary = Some(summary.to_string());
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.operation.description = Some(desc.to_string());
        self
    }

    pub fn tag(mut self, tag: &str) -> Self {
        self.operation.tags.push(tag.to_string());
        self
    }

    pub fn path_param(
        mut self,
        name: &str,
        schema_type: SchemaType,
        description: Option<&str>,
    ) -> Self {
        self.operation.parameters.push(Parameter {
            name: name.to_string(),
            location: ParameterIn::Path,
            description: description.map(String::from),
            required: true,
            deprecated: false,
            schema: PropertySchema::new(schema_type),
        });
        self
    }

    pub fn query_param(mut self, name: &str, schema_type: SchemaType, required: bool) -> Self {
        self.operation.parameters.push(Parameter {
            name: name.to_string(),
            location: ParameterIn::Query,
            description: None,
            required,
            deprecated: false,
            schema: PropertySchema::new(schema_type),
        });
        self
    }

    pub fn request_body(mut self, content_type: &str, schema: PropertySchema) -> Self {
        let mut content = HashMap::new();
        content.insert(
            content_type.to_string(),
            MediaType {
                schema,
                example: None,
            },
        );
        self.operation.request_body = Some(RequestBody {
            description: None,
            required: true,
            content,
        });
        self
    }

    pub fn response(mut self, status: &str, description: &str) -> Self {
        self.operation.responses.insert(
            status.to_string(),
            Response {
                description: description.to_string(),
                content: HashMap::new(),
                headers: HashMap::new(),
            },
        );
        self
    }

    pub fn response_with_schema(
        mut self,
        status: &str,
        description: &str,
        content_type: &str,
        schema: PropertySchema,
    ) -> Self {
        let mut content = HashMap::new();
        content.insert(
            content_type.to_string(),
            MediaType {
                schema,
                example: None,
            },
        );
        self.operation.responses.insert(
            status.to_string(),
            Response {
                description: description.to_string(),
                content,
                headers: HashMap::new(),
            },
        );
        self
    }

    pub fn security(mut self, scheme: &str, scopes: Vec<&str>) -> Self {
        let mut sec = HashMap::new();
        sec.insert(
            scheme.to_string(),
            scopes.iter().map(|s| s.to_string()).collect(),
        );
        self.operation.security.push(sec);
        self
    }

    pub fn deprecated(mut self) -> Self {
        self.operation.deprecated = true;
        self
    }

    pub fn build(self) -> Operation {
        self.operation
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== API Documentation Generator ===\n");

    // Example 1: Build OpenAPI spec
    println!("1. Building OpenAPI Specification:");

    let mut spec = OpenApiBuilder::new("Pet Store API", "1.0.0")
        .description("A sample Pet Store API")
        .contact(
            "API Support",
            "support@example.com",
            Some("https://example.com"),
        )
        .license("MIT", Some("https://opensource.org/licenses/MIT"))
        .server("https://api.example.com/v1", Some("Production"))
        .server("https://staging-api.example.com/v1", Some("Staging"))
        .tag("pets", Some("Pet operations"))
        .tag("users", Some("User operations"));

    // Add endpoints
    let list_pets = OperationBuilder::new("listPets")
        .summary("List all pets")
        .tag("pets")
        .query_param("limit", SchemaType::Integer, false)
        .query_param("offset", SchemaType::Integer, false)
        .response("200", "Successful response")
        .response("400", "Invalid request")
        .build();

    spec = spec.path("/pets", HttpMethod::Get, list_pets);

    let get_pet = OperationBuilder::new("getPet")
        .summary("Get a pet by ID")
        .tag("pets")
        .path_param("petId", SchemaType::Integer, Some("The pet ID"))
        .response("200", "Successful response")
        .response("404", "Pet not found")
        .build();

    spec = spec.path("/pets/{petId}", HttpMethod::Get, get_pet);

    let create_pet = OperationBuilder::new("createPet")
        .summary("Create a new pet")
        .tag("pets")
        .request_body(
            "application/json",
            PropertySchema::new(SchemaType::Object(HashMap::new())),
        )
        .response("201", "Pet created")
        .response("400", "Invalid input")
        .security("bearerAuth", vec![])
        .build();

    spec = spec.path("/pets", HttpMethod::Post, create_pet);

    // Add security scheme
    spec = spec.security_scheme(
        "bearerAuth",
        SecurityScheme::Http {
            scheme: "bearer".to_string(),
            bearer_format: Some("JWT".to_string()),
        },
    );

    println!("   Title: Pet Store API");
    println!("   Version: 1.0.0");
    println!("   Endpoints: 3");

    // Example 2: Generate JSON
    println!("\n2. OpenAPI JSON (excerpt):");
    let json = spec.to_json();
    for line in json.lines().take(20) {
        println!("   {}", line);
    }
    println!("   ...");

    // Example 3: Generate YAML
    println!("\n3. OpenAPI YAML (excerpt):");
    let yaml = spec.to_yaml();
    for line in yaml.lines().take(15) {
        println!("   {}", line);
    }
    println!("   ...");

    // Example 4: Generate Rust documentation
    println!("\n4. Rust Documentation:");
    let mut doc_gen = DocGenerator::new("my_crate", "0.1.0");

    doc_gen.add_item(DocItem {
        name: "MyStruct".to_string(),
        kind: DocItemKind::Struct,
        visibility: Visibility::Public,
        doc_comment: Some("A demonstration struct for API operations.".to_string()),
        signature: "MyStruct { field1: String, field2: i32 }".to_string(),
        examples: vec!["let s = MyStruct { field1: \"hello\".into(), field2: 42 };".to_string()],
        attributes: vec!["#[derive(Debug)]".to_string()],
        children: vec![DocItem {
            name: "field1".to_string(),
            kind: DocItemKind::Method,
            visibility: Visibility::Public,
            doc_comment: Some("The first field".to_string()),
            signature: "field1: String".to_string(),
            examples: vec![],
            attributes: vec![],
            children: vec![],
        }],
    });

    doc_gen.add_item(DocItem {
        name: "process".to_string(),
        kind: DocItemKind::Function,
        visibility: Visibility::Public,
        doc_comment: Some("Process data and return result.".to_string()),
        signature: "fn process(input: &str) -> Result<Output, Error>".to_string(),
        examples: vec!["let result = process(\"input\")?;".to_string()],
        attributes: vec![],
        children: vec![],
    });

    let markdown = doc_gen.to_markdown();
    println!(
        "   Markdown documentation generated ({} bytes)",
        markdown.len()
    );

    // Example 5: Schema types
    println!("\n5. Schema Types:");

    let string_prop = PropertySchema::new(SchemaType::String)
        .required()
        .description("User's email address")
        .format("email")
        .example("user@example.com");

    println!(
        "   String schema: type={}, required={}",
        string_prop.schema_type.as_json_type(),
        string_prop.required
    );

    let array_prop = PropertySchema::new(SchemaType::Array(Box::new(SchemaType::String)))
        .description("List of tags");

    println!(
        "   Array schema: type={}",
        array_prop.schema_type.as_json_type()
    );

    // Example 6: Complex object schema
    println!("\n6. Object Schema:");
    let mut properties = HashMap::new();
    properties.insert(
        "id".to_string(),
        PropertySchema::new(SchemaType::Integer).required(),
    );
    properties.insert(
        "name".to_string(),
        PropertySchema::new(SchemaType::String).required(),
    );
    properties.insert(
        "email".to_string(),
        PropertySchema::new(SchemaType::String).format("email"),
    );

    let user_schema =
        PropertySchema::new(SchemaType::Object(properties)).description("User object");

    println!("   User schema created with 3 properties");

    // Example 7: Security schemes
    println!("\n7. Security Schemes:");

    let api_key = SecurityScheme::ApiKey {
        name: "X-API-Key".to_string(),
        location: ParameterIn::Header,
    };
    println!("   API Key: X-API-Key in header");

    let oauth2 = SecurityScheme::OAuth2 {
        flows: OAuth2Flows {
            authorization_code: Some(OAuth2Flow {
                authorization_url: Some("https://auth.example.com/authorize".to_string()),
                token_url: Some("https://auth.example.com/token".to_string()),
                refresh_url: None,
                scopes: {
                    let mut s = HashMap::new();
                    s.insert("read:pets".to_string(), "Read pets".to_string());
                    s.insert("write:pets".to_string(), "Write pets".to_string());
                    s
                },
            }),
            ..Default::default()
        },
    };
    println!("   OAuth2: Authorization code flow configured");

    // Example 8: HTML documentation
    println!("\n8. HTML Documentation:");
    let html = doc_gen.to_html();
    println!("   HTML documentation generated ({} bytes)", html.len());
    println!("   Contains: sidebar, content sections, code formatting");

    // Example 9: Operation with all features
    println!("\n9. Full Operation Example:");
    let full_op = OperationBuilder::new("updatePet")
        .summary("Update an existing pet")
        .description("Update a pet by ID with new data")
        .tag("pets")
        .path_param("petId", SchemaType::Integer, Some("Pet ID to update"))
        .request_body(
            "application/json",
            PropertySchema::new(SchemaType::Object(HashMap::new())),
        )
        .response("200", "Pet updated successfully")
        .response("400", "Invalid ID supplied")
        .response("404", "Pet not found")
        .response("422", "Validation exception")
        .security("bearerAuth", vec!["write:pets"])
        .build();

    println!("   Operation ID: {}", full_op.operation_id);
    println!("   Parameters: {}", full_op.parameters.len());
    println!("   Responses: {}", full_op.responses.len());

    // Example 10: API versioning
    println!("\n10. API Versioning:");
    let v1_spec =
        OpenApiBuilder::new("API", "1.0.0").server("https://api.example.com/v1", Some("Version 1"));

    let v2_spec = OpenApiBuilder::new("API", "2.0.0")
        .server("https://api.example.com/v2", Some("Version 2"))
        .description("New improved API with breaking changes");

    println!("   v1: 1.0.0");
    println!("   v2: 2.0.0 (with breaking changes)");

    println!("\n=== Documentation Generation Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_builder() {
        let spec = OpenApiBuilder::new("Test API", "1.0.0").description("Test description");

        let json = spec.to_json();
        assert!(json.contains("Test API"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn test_operation_builder() {
        let op = OperationBuilder::new("testOp")
            .summary("Test operation")
            .tag("test")
            .response("200", "OK")
            .build();

        assert_eq!(op.operation_id, "testOp");
        assert_eq!(op.summary, Some("Test operation".to_string()));
        assert!(op.tags.contains(&"test".to_string()));
    }

    #[test]
    fn test_path_param() {
        let op = OperationBuilder::new("test")
            .path_param("id", SchemaType::Integer, Some("ID"))
            .build();

        assert_eq!(op.parameters.len(), 1);
        assert!(op.parameters[0].required);
    }

    #[test]
    fn test_query_param() {
        let op = OperationBuilder::new("test")
            .query_param("limit", SchemaType::Integer, false)
            .build();

        assert_eq!(op.parameters.len(), 1);
        assert!(!op.parameters[0].required);
    }

    #[test]
    fn test_schema_type() {
        assert_eq!(SchemaType::String.as_json_type(), "string");
        assert_eq!(SchemaType::Integer.as_json_type(), "integer");
        assert_eq!(SchemaType::Boolean.as_json_type(), "boolean");
    }

    #[test]
    fn test_property_schema() {
        let prop = PropertySchema::new(SchemaType::String)
            .required()
            .nullable()
            .description("Test")
            .example("example");

        assert!(prop.required);
        assert!(prop.nullable);
        assert_eq!(prop.description, Some("Test".to_string()));
    }

    #[test]
    fn test_http_method() {
        assert_eq!(HttpMethod::Get.as_str(), "get");
        assert_eq!(HttpMethod::Post.as_str(), "post");
    }

    #[test]
    fn test_doc_generator() {
        let gen = DocGenerator::new("test_crate", "0.1.0");
        let md = gen.to_markdown();
        assert!(md.contains("test_crate"));
    }

    #[test]
    fn test_doc_item_kind() {
        assert_eq!(DocItemKind::Struct.as_str(), "struct");
        assert_eq!(DocItemKind::Function.as_str(), "fn");
    }

    #[test]
    fn test_openapi_yaml() {
        let spec = OpenApiBuilder::new("Test", "1.0.0").server("https://api.test.com", None);

        let yaml = spec.to_yaml();
        assert!(yaml.contains("openapi:"));
        assert!(yaml.contains("servers:"));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }

    #[test]
    fn test_parameter_in() {
        assert_eq!(ParameterIn::Query.as_str(), "query");
        assert_eq!(ParameterIn::Path.as_str(), "path");
        assert_eq!(ParameterIn::Header.as_str(), "header");
    }

    #[test]
    fn test_security_scheme() {
        let api_key = SecurityScheme::ApiKey {
            name: "key".to_string(),
            location: ParameterIn::Header,
        };
        matches!(api_key, SecurityScheme::ApiKey { .. });
    }

    #[test]
    fn test_openapi_version() {
        assert_eq!(OpenApiVersion::V3_0.as_str(), "3.0.3");
        assert_eq!(OpenApiVersion::V3_1.as_str(), "3.1.0");
    }

    #[test]
    fn test_array_schema() {
        let array = SchemaType::Array(Box::new(SchemaType::String));
        assert_eq!(array.as_json_type(), "array");
    }

    #[test]
    fn test_request_body() {
        let op = OperationBuilder::new("test")
            .request_body(
                "application/json",
                PropertySchema::new(SchemaType::Object(HashMap::new())),
            )
            .build();

        assert!(op.request_body.is_some());
    }

    #[test]
    fn test_deprecated_operation() {
        let op = OperationBuilder::new("test").deprecated().build();

        assert!(op.deprecated);
    }
}
