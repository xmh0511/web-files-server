
use salvo::{prelude::*, catcher::Catcher};

use salvo::serve_static::StaticDir;

use salvo::basic_auth::{BasicAuth, BasicAuthValidator};

pub mod static_handler;
use http::{HeaderValue, Method};

use serde_json::json;
use tera::Tera;
use path_absolutize::*;
use redis::{ AsyncCommands};
use config_file::FromConfigFile;
use serde::Deserialize;

use std::path::{Path, PathBuf};

use fs_extra::dir::CopyOptions;
struct Validator(Config);
#[async_trait]
impl BasicAuthValidator for Validator {
    async fn validate(&self, username: &str, password: &str,_depot: &mut Depot) -> bool {
		let name = &self.0.manage.name;
		let pass = &self.0.manage.password;
		if username == name && password == pass{
          true
		}else{
			match redis::Client::open("redis://127.0.0.1/"){
				Ok(client)=>{
					let Ok(mut con) = client.get_async_connection().await else{
						return false;
					};
			      let key = format!("fs_account.{username}");
				  match con.get(key).await{
					  Ok(v)=>{
						 let v:Option<String> = v;
						 match v {
							Some(v)=>{
								if v == password{
									return true;
								}else{
									return false;
								}
							}
							None=>{
								return false;
							}
						 }
					  }
					  Err(_)=>{
						return false;
					  }
				  }
				}
				Err(_)=>{
					return false;
				}
			}
		}
    }
}

struct AdminValidator(Config);
#[async_trait]
impl BasicAuthValidator for AdminValidator {
    async fn validate(&self, username: &str, password: &str,_depot: &mut Depot) -> bool {
		let name = &self.0.admin.name;
		let pass = &self.0.admin.password;
        username == name && password == pass
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
            res.status_code(StatusCode::BAD_REQUEST);
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
    depot: &mut Depot,
) -> Result<(), AnyHowErrorWrapper> {
	let is_preview = req.query::<bool>("preview").unwrap_or(false);
	//println!("is_preview = {is_preview}");
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
                let content_disposition = if is_preview{
					format!("inline")
				}else{format!("attachment; filename={}", file_name)} 
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
				let default = String::from("");
				let base_path = depot.get::<String>("base_path").unwrap_or(&default);
				context.insert("baseUrl", &base_path);
                //println!("invocation {context:?}");
                let mut tera = Tera::default();
                tera.add_template_file("views/list.html", Some("list.html"))?;
                let r = match tera.render("list.html", &context) {
                    Ok(r) => r,
                    Err(e) => {
                        //println!("{e:?}");
                        //panic!("error")
						return Err(anyhow::anyhow!("tera render error: {e:?}").into());
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
            static_handler::ResponseError::StateError(_) => {
                res.status_code(StatusCode::BAD_REQUEST);
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
    //println!("{path}, {origin_name}");
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
    //println!("{absolute_path}");
    let canonical_path = Path::new(&absolute_path);
    let static_path = Path::new("static").canonicalize()?;
	let public_path = Path::new("public").canonicalize()?;
    let is_contain = canonical_path.starts_with(static_path) || canonical_path.starts_with(public_path);
    if !is_contain {
        return Err(anyhow::anyhow!("invalid path that is not within the permitted root directory").into());
    }
    let r = complete_path.to_owned();
    Ok(r)
}


#[handler]
async fn create_directory(req: &mut Request, res: &mut Response)->Result<(), AnyHowErrorWrapper<true>>{
	let path = req.form::<String>("path").await.result()?;
    let dir_name = req.form::<String>("dir_name").await.result()?;
	let complete_path = validate_path(&path,&dir_name)?;
	if complete_path.exists(){
        return Err(anyhow::anyhow!("object has been existed").into());
    }
	let _ = std::fs::create_dir_all(complete_path)?;
	let json = json!({
		"code":200
	});
	res.render(Text::Json(json.to_string()));
	Ok(())
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
		let json = json!({
			"code":200,
		});
		res.render(Text::Json(json.to_string()));
    }else{
		let json = json!({
			"code":404,
			"msg":"不存在该文件对象"
		});
		res.render(Text::Json(json.to_string()));
	}
    Ok(())
}

#[handler]
async fn rename(req: &mut Request, res: &mut Response)-> Result<(), AnyHowErrorWrapper<true>>{
	let o_name = req.form::<String>("o_name").await.result()?;
	let n_name = req.form::<String>("n_name").await.result()?;
    let path = req.form::<String>("path").await.result()?;
	let o_complete_path = validate_path(&path, &o_name)?;
	let n_complete_path = validate_path(&path, &n_name)?;
	if o_complete_path.exists(){
		if n_complete_path.exists(){
			let json = json!({
				"code":404,
				"msg":"与其他文件对象重名"
			});
			res.render(Text::Json(json.to_string()));
		}else{
            std::fs::rename(o_complete_path, n_complete_path)?;
			let json = json!({
				"code":200,
			});
			res.render(Text::Json(json.to_string()));
		}
	}else{
		let json = json!({
			"code":404,
			"msg":"不存在该文件对象"
		});
		res.render(Text::Json(json.to_string()));
	}
	Ok(())
}

#[handler]
async fn share(req: &mut Request, res: &mut Response)-> Result<(), AnyHowErrorWrapper<true>>{
	let o_name = req.form::<String>("name").await.result()?;
    let path = req.form::<String>("path").await.result()?;
	let kind = req.form::<String>("kind").await.result()?;
	let o_complete_path = validate_path(&path, &o_name)?;
	let n_complete_path = validate_path("/public/", &o_name)?;
	if o_complete_path.exists(){
		if &kind == "dir"{
			let option = CopyOptions::default().overwrite(true);
			match std::fs::create_dir(&n_complete_path){
				Ok(_) => {},
				Err(e) => {
					if e.kind() != std::io::ErrorKind::AlreadyExists{
						return Err(e.into());
					}
				},
			};
			//println!("{o_complete_path:?}, {n_complete_path:?}");
			fs_extra::dir::copy(o_complete_path, "./public",&option)?;
			let json = json!({
				"code":200,
			});
			res.render(Text::Json(json.to_string()));
		}else if &kind == "file"{
			std::fs::copy(o_complete_path, n_complete_path)?;
			let json = json!({
				"code":200,
			});
			res.render(Text::Json(json.to_string()));
		}else{
			let json = json!({
				"code":404,
				"msg":"不支持的类型"
			});
			res.render(Text::Json(json.to_string()));
		}
	}else{
		let json = json!({
			"code":404,
			"msg":"不存在该文件对象"
		});
		res.render(Text::Json(json.to_string()));
	}
	Ok(())
}

#[handler]
async fn admin(req: &mut Request, res: &mut Response, depot: & mut Depot)-> Result<(), AnyHowErrorWrapper<true>>{
	if req.method() == Method::GET{
		let mut context = tera::Context::new();
		let default = String::from("");
		let base_path = depot.get::<String>("base_path").unwrap_or(&default);
		context.insert("baseUrl",&base_path);
		//println!("invocation {context:?}");
		let mut tera = Tera::default();
		tera.add_template_file("views/admin.html", Some("admin.html"))?;
		let r = match tera.render("admin.html", &context) {
			Ok(r) => r,
			Err(e) => {
				//println!("{e:?}");
				//panic!("error")
				return Err(anyhow::anyhow!("tera render error: {e:?}").into());
			}
		};
		res.render(Text::Html(r));
		Ok(())
	}else{
		let user:String = req.form("user").await.result()?;
		let pass:String = req.form("pass").await.result()?;
		let seconds:i64 = req.form("seconds").await.result()?;
		//println!("{user},{pass},{seconds}");
		let client = redis::Client::open("redis://127.0.0.1/")?;
		let mut con = client.get_async_connection().await?;
		let key = format!("fs_account.{user}");
		if seconds !=-1 && seconds >0{
			con.set_ex(key, pass, seconds as usize).await?;
		}else{
			con.set(key, pass).await?;
		}
		res.render(Text::Plain("OK"));
		Ok(())
	}
}

struct Handle404;

#[handler]
impl Handle404 {
    async fn handle(&self, _req: & mut Request, _depot: & mut Depot, res: &mut Response, ctrl: &mut FlowCtrl) {
        if let Some(StatusCode::NOT_FOUND) = res.status_code {
			// let default = String::from("");
			// let base_path = depot.get::<String>("route_base_path").unwrap_or(&default);
            res.render(Text::Plain("page not found"));
            ctrl.skip_rest();
        }
    }
}
#[derive(Deserialize,Clone)]
struct AdminConfig{
	name:String,
	password:String
}

#[derive(Deserialize,Clone)]
struct ManageConfig{
	name:String,
	password:String
}

#[derive(Deserialize,Clone)]
struct Config{
	bind:String,
	base_path:String,
	route_base_path:String,
	admin:AdminConfig,
	manage:ManageConfig
}

struct BasePath{
	base_path:String,
	route_base_path:String
}
#[handler]
impl BasePath {
    async fn handle(&self, req: & mut Request, depot: & mut Depot, res: &mut Response, ctrl: &mut FlowCtrl) {
		depot.insert("base_path", self.base_path.clone());
		depot.insert("route_base_path", self.route_base_path.clone());
		ctrl.call_next(req, depot, res).await;
    }
}


#[tokio::main]
async fn main() {
	let config:Config = FromConfigFile::from_config_file("./config.toml").expect("config file not found");
	match std::fs::create_dir("static"){
		Ok(_) => {},
		Err(e) => {
			if e.kind() != std::io::ErrorKind::AlreadyExists{
				panic!("{e:?}");
			}
		},
	};

    let auth_handler = BasicAuth::new(Validator(config.clone()));
    let web_file_router = Router::with_path("static/<**>").get(handle_static);
	let upload_router  = Router::with_path("upload").post(upload);
    let delete_router = Router::with_path("delete").post(delete);
	let createdir_router = Router::with_path("createdir").post(create_directory);
	let rename_router = Router::with_path("rename").post(rename);
	let share_router = Router::with_path("share").post(share);

	
    let require_validate_router = Router::new().hoop(auth_handler);

    let require_validate_router = require_validate_router.push(web_file_router);
	let require_validate_router = require_validate_router.push(upload_router);
    let require_validate_router = require_validate_router.push(delete_router);
	let require_validate_router = require_validate_router.push(createdir_router);
	let require_validate_router = require_validate_router.push(rename_router);
	let require_validate_router = require_validate_router.push(share_router);

	let admin_auth_handler = BasicAuth::new(AdminValidator(config.clone()));
	let admin_router = Router::with_path("admin").hoop(admin_auth_handler).get(admin).post(admin);

    let static_router = Router::with_path("public/<**>").get(StaticDir::new(["public"]).listing(true));

	let root_router = Router::with_path(&config.route_base_path).hoop(BasePath{base_path:config.base_path.clone(),route_base_path:config.route_base_path.clone()}).push(static_router);
	let root_router = root_router.push(require_validate_router);
	let root_router = root_router.push(admin_router);
	//let root_router = root_router.push(upload_router);

	let service = Service::new(root_router).catcher(Catcher::default().hoop(Handle404));
	let acceptor = TcpListener::new(&config.bind).bind().await;
    Server::new(acceptor)
        .serve(service)
        .await;
}
