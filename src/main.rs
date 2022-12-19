
use salvo::{prelude::*};

use salvo::serve_static::StaticDir;

use salvo::basic_auth::{BasicAuth, BasicAuthValidator};

pub mod static_handler;
use http::HeaderValue;

use serde_json::json;
use tera::Tera;
use path_absolutize::*;


use std::path::{Path, PathBuf};
struct Validator;
#[async_trait]
impl BasicAuthValidator for Validator {
    async fn validate(&self, username: &str, password: &str) -> bool {
        username == "admin" && password == "970252187"
    }
}

// struct InjectTera(Tera);

// #[async_trait]
// impl Handler for InjectTera {
//     async fn handle(
//         &self,
//         req: &mut Request,
//         depot: &mut Depot,
//         res: &mut Response,
//         ctrl: &mut FlowCtrl,
//     ) {
//         depot.insert("tera", self.0.clone());
//         ctrl.call_next(req, depot, res).await;
//     }
// }

trait ToResult<const JSON:bool,T> {
    fn result(self) -> Result<T, AnyHowErrorWrapper<JSON>>;
}

impl<const JSON:bool,T> ToResult<JSON,T> for Option<T> {
    fn result(self) -> Result<T, AnyHowErrorWrapper<JSON>> {
        match self {
            Some(x) => Ok(x),
            None => {
				let name = std::any::type_name::<T>();
				Err(AnyHowErrorWrapper(anyhow::anyhow!("Option<{name}> is None")))
			},
        }
    }
}

// #[cfg(feature = "anyhow")]
// #[async_trait]
// impl Writer for ::anyhow::Error {
//     async fn write(mut self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
//         res.set_http_error(StatusError::internal_server_error());
//     }
// }

struct AnyHowErrorWrapper<const JSON:bool = false>(anyhow::Error);

#[async_trait]
impl<const JSON:bool> Writer for AnyHowErrorWrapper<JSON> {
    async fn write(mut self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        if JSON {
            let json = json!({
                "code":404,
                "msg":self.0.to_string()
            });
            res.render(Text::Json(json.to_string()));
        }else{
            res.set_status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain(self.0.to_string()));
        }
    }
}

impl<const JSON:bool,T: Into<anyhow::Error>> From<T> for AnyHowErrorWrapper<JSON> {
    fn from(value: T) -> Self {
        AnyHowErrorWrapper(value.into())
    }
}

#[handler]
async fn handle_static(
    req: &mut Request,
    res: &mut Response,
    _depot: &mut Depot,
) -> Result<(), AnyHowErrorWrapper> {
    let r = static_handler::StaticDir::new("static").with_listing(true);
    let v: Result<
        static_handler::ResponseContent<
            static_handler::FilesListStructure<{ static_handler::JSON_VALUE }>,
        >,
        static_handler::ResponseError,
    > = r.handle_request(req, res).await;
    match v {
        Ok(v) => match v {
            static_handler::ResponseContent::File(mut file) => {
                let path = file.path();
                let file_name = path.file_name().unwrap().to_str().to_owned().unwrap();
                let content_disposition = format!("attachment; filename={}", file_name)
                    .parse::<HeaderValue>()
                    .unwrap();
                file.set_content_disposition(content_disposition);
                file.send(req.headers(), res).await;
                return Ok(());
            }
            static_handler::ResponseContent::Dir(list) => {
                //let tera = depot.get::<Tera>("tera").unwrap();
                let mut context = tera::Context::new();
                context.insert("info", &list);
                //println!("invocation {context:?}");
                let mut tera = Tera::default();
                tera.add_template_file("views/list.html", Some("list.html"))?;
                let r = match tera.render("list.html", &context) {
                    Ok(r) => r,
                    Err(e) => {
                        println!("{e:?}");
                        panic!("error")
                    }
                };
                res.render(Text::Html(r));
                return Ok(());
            }
        },
        Err(e) => match e {
            static_handler::ResponseError::Redirect(r) => {
                res.render(r);
                return Ok(());
            }
            static_handler::ResponseError::StateError(s) => {
                res.set_status_error(s);
                return Ok(());
            }
        },
    }
}

#[handler]
async fn upload(req: &mut Request, res: &mut Response) -> Result<(), AnyHowErrorWrapper<true>> {
	let path = req.form::<String>("path").await.result()?;
    let file = req.file("file").await;
    let file = match file{
        Some(file) => file,
        None => {
            return Err(anyhow::anyhow!("file not found in request").into());
        },
    };
    let origin_name = file.name().result()?;
    println!("{path}, {origin_name}");
    let complete_path = validate_path(&path,origin_name)?;
    if complete_path.exists(){
        return Err(anyhow::anyhow!("object has been existed").into());
    }
    let info = if let Err(e) = std::fs::copy(&file.path(), &complete_path) {
        let j = json!({
            "code":404,
            "msg":format!("file not found in request: {}", e)
        });
        j.to_string()
    } else {
        let j = json!({
            "code":200,
            "msg":""
        });
        j.to_string()
    };
    res.render(Text::Json(info));
	Ok(())
}

fn validate_path<const JSON:bool>(prefix_path:&str, target:&str)->Result<PathBuf, AnyHowErrorWrapper<JSON>>{
	let path = if &prefix_path[0..1] == "/"{
		prefix_path[1..].to_owned()
	}else{
		return Err(anyhow::anyhow!("invalid path without prefix /").into());
	};
    let last = path.len() - 1;
	if &path[last..] != "/"{
		return Err(anyhow::anyhow!("invalid path without postfix /").into());
	}
    let r = Path::new(&path).exists();
    if !r{
        return Err(anyhow::anyhow!("不存在该目录").into()); 
    }
    let complete_path = format!("{path}{target}");
    let complete_path = Path::new(&complete_path);
    let absolute_path = complete_path.absolutize()?.to_str().result()?.to_string();
    println!("{absolute_path}");
    let canonical_path = Path::new(&absolute_path);
    let static_path = Path::new("static").canonicalize()?;
    let is_contain = canonical_path.starts_with(static_path);
    if !is_contain {
        return Err(anyhow::anyhow!("invalid path that is not within the permitted root directory").into());
    }
    let r = complete_path.to_owned();
    Ok(r)
}


#[handler]
async fn delete(req: &mut Request, res: &mut Response)-> Result<(), AnyHowErrorWrapper<true>>{
    let name = req.form::<String>("name").await.result()?;
    let path = req.form::<String>("path").await.result()?;
    let complete_path = validate_path(&path, &name)?;
    if complete_path.exists(){
        let is_file  = complete_path.is_file();
        if is_file{
            std::fs::remove_file(complete_path)?;
        }else{
            std::fs::remove_dir_all(complete_path)?;
        }
    }
    let json = json!({
        "code":200,
    });
    res.render(Text::Json(json.to_string()));
    Ok(())
}

#[tokio::main]
async fn main() {
    let mut tera = match Tera::new("views/**/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };
    tera.autoescape_on(vec![]);
    let auth_handler = BasicAuth::new(Validator);
    let web_file_router = Router::with_path("static/<**>").get(handle_static);
	let upload_router  = Router::with_path("upload").post(upload);
    let delete_router = Router::with_path("delete").post(delete);

	
    let require_validate_router = Router::new().hoop(auth_handler);

    let require_validate_router = require_validate_router.push(web_file_router);
	let require_validate_router = require_validate_router.push(upload_router);
    let require_validate_router = require_validate_router.push(delete_router);

	let root_router = Router::new().push(require_validate_router);
	//let root_router = root_router.push(upload_router);

    let static_router =
        Router::with_path("public/<**>").get(StaticDir::new(["public"]).with_listing(true));
    let root_router = root_router.push(static_router);
    Server::new(TcpListener::bind("127.0.0.1:7878"))
        .serve(root_router)
        .await;
}
