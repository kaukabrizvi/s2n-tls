// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let file_descriptors = protox::compile(["proto/metric_record.proto"], ["proto/"]).unwrap();
    prost_build::compile_fds(file_descriptors).unwrap();
}
