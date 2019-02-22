//
// Copyright (C) 2018 Kubos Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

extern crate comms_service;

extern crate pnet;

use comms_service::*;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};

// Read port for the socket used in the 'read' function.
const READ_PORT: u16 = 13000;
// Write port for the socket used in the 'write' function.
const WRITE_PORT: u16 = 13001;

// Function to allow reading from a UDP socket.
pub fn read(socket: &Arc<UdpSocket>) -> CommsResult<Vec<u8>> {
    let mut buf = [0; 4096];
    let (size, _) = socket.recv_from(&mut buf)?;
    Ok(buf[0..size].to_vec())
}

// Function to allow writing over a UDP socket.
pub fn write(socket: &Arc<UdpSocket>, data: &[u8]) -> CommsResult<()> {
    let config = comms_config();
    socket.send_to(
        data,
        (&*config.ground_ip, config.ground_port.unwrap_or_default()),
    )?;
    Ok(())
}

fn comms_config() -> CommsConfig {
    CommsConfig {
        handler_port_min: None,
        handler_port_max: None,
        downlink_ports: Some(vec![16000]),
        timeout: Some(1000),
        ground_ip: "0.0.0.0".to_owned(),
        ground_port: Some(16001),
        satellite_ip: "0.0.0.0".to_owned(),
    }
}

#[test]
fn good_downlink() {
    let config = comms_config();

    let satellite_ip = config.satellite_ip.clone();

    // Create socket to mock reading from a radio.
    let read_conn = Arc::new(UdpSocket::bind((satellite_ip.as_str(), READ_PORT)).unwrap());

    // Create socket to mock writing to a radio.
    let write_conn = Arc::new(UdpSocket::bind((satellite_ip.as_str(), WRITE_PORT)).unwrap());

    // Control block to configure communication service.
    let controls = CommsControlBlock::new(
        Some(Arc::new(read)),
        vec![Arc::new(write)],
        read_conn,
        write_conn,
        config,
    )
    .unwrap();

    // Initialize new `CommsTelemetry` object.
    let telem = Arc::new(Mutex::new(CommsTelemetry::default()));

    // Start communication service.
    CommsService::start(controls, &telem).unwrap();

    let ground_listener = UdpSocket::bind(("0.0.0.0", 16001)).unwrap();
    let downlink_writer = UdpSocket::bind(("0.0.0.0", 0)).unwrap();

    downlink_writer
        .send_to(&vec![1, 2, 3, 4], (satellite_ip.as_str(), 16000))
        .unwrap();

    let mut buf = [0; 4096];
    let (size, _) = ground_listener.recv_from(&mut buf).unwrap();
    let data = buf[0..size].to_vec();

    let packet = UdpPacket::new(&data).unwrap();

    assert_eq!(packet.payload().to_vec(), vec![1, 2, 3, 4]);
}
