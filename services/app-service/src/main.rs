/*
 * Copyright (C) 2018 Kubos Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#![deny(warnings)]

#[macro_use]
extern crate juniper;

mod app_entry;
mod error;
mod objects;
mod registry;
mod schema;
#[cfg(test)]
mod tests;

use crate::registry::AppRegistry;
use failure::{bail, Error};
use getopts::Options;
use kubos_service::{Config, Service};
use log::error;
use std::env;
use syslog::Facility;

fn main() -> Result<(), Error> {
    syslog::init(
        Facility::LOG_DAEMON,
        log::LevelFilter::Debug,
        Some("kubos-app-service"),
    )
    .unwrap();

    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();

    opts.optflag("b", "onboot", "Execute OnBoot logic");
    opts.optopt("c", "config", "Path to config file", "CONFIG");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => {
            bail!("Unable to parse command options: {}", err);
        }
    };

    let config = match matches.opt_str("c") {
        Some(file) => Config::new_from_path("app-service", file),
        None => Config::new("app-service"),
    };

    let registry = {
        match config.get("registry-dir") {
            Some(dir) => AppRegistry::new_from_dir(dir.as_str().unwrap())?,
            None => AppRegistry::new()?,
        }
    };

    if matches.opt_present("b") {
        registry
            .run_onboot()
            .unwrap_or_else(|err| error!("Error starting applications: {}", err));
    }

    Service::new(config, registry, schema::QueryRoot, schema::MutationRoot).start();

    Ok(())
}
