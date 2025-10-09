This guide provides a step-by-step walkthrough for creating a new extractor in OSV-Scalibr. For a real-world example, you can refer to the nvm extractor pull request: https://github.com/google/osv-scalibr/pull/1322
See what files changed in that pull request and take that as a reference.

```markdown
### Plugin Specification

*   **Extractor Name:** onepasswordconnecttoken
*   **File to parse:** Any files containing "onepassword", "1password" in their name that is .json extension,
*   **Inventory Type:**  `secrets`

The json file looks like this : (only process the infmroation that is important):

{"verifier":{"salt":"JD6cq4PDx8biZ_WIEo8sJQ","localHash":"lLjGM419fBfty9S-a7BwXBLsl40QL0xWmReBF2r9hM8"},"encCredentials":{"kid":"localauthv2keykid","enc":"A256GCM","cty":"b5+jwk+json","iv":"nHE-eIYl0_YgVo14","data":"yQVzCjBZa5mRMHsT5DQF9y9NWR0oY1ZudueqUCuKEUm4agXFGagMLiZJgwX4zn8nCfhtEWgA0OUo10HlR-oMx6hpHw8QsW8Y3e61t0en40LHAzMwjIZtIn_NFKAzSAMJRU3sv4Kz70YsZZopK9Jsgx4czkCcYqgr-3KxVczVpBhsq6PhPYh-xsr8a2tDQ2_ZWYQgTyUH51vV0ZfNOH81Wa6M6Xc2uAtBLx3uxP7odK0h1CH6RhEmokX1lwPy8C5d0wKRF-DJGpzEUZ9wenic8BtDVO00rAOQJT1sUZM6YHPcxL6mco3kWhuXtPVHBcWbDPWWK-WHoRTI_qUKBg3yof-19Y9DBwT2ScwBFbssZgCcQ7pXy8GK_VP0n381zMDbD5w0ZD3qA58jYWTK36_ZWkbcFv_jG1rvk1O5DuGnlQT3cQxv9ELUKT6FB9qqvGjvkWZzKDfljHQ7QThlOzG5iVFYkWKXEAW60BOQmRwI4xikrPvf3KjywE2IFxliUWxt5AMHSWrknyEoHSLkpSThLDL4EhePptc9UBW6rkYhVsC6ZUkiOIIQ1hOBPRqctAteacuCGD1I9CI3x5CgnEL7TNPX_njDO_fkvQBJUBauLaPP7ObjyPDnWLOAKROELWjrFA"},"version":"2","deviceUuid":"yrkdmusoblmgm6siuj4kcssxke","uniqueKey":{"alg":"A256GCM","ext":true,"k":"K4Rb77lh7zaypYiS2k78c7m8T865kfH0idS6a9c49F0","key_ops":["encrypt","decrypt"],"kty":"oct","kid":"pol5dybe7lxax42ha6r7rwwdm4"}}

```

---

## Part 2: Code Implementation

> **Important:** Always follow the [OSV-Scalibr Style Guide](https://github.com/google/osv-scalibr/blob/main/docs/style_guide.md) when writing code for this project.

### Step 2.1: Create New Go Files for Your Plugin

Create a new directory at `extractor/filesystem/[INVENTORY_TYPE]/`. The following files should be created inside it.

#### A. Metadata Definition (`metadata/metadata.go`)

Create a Go `struct` for the metadata of the package you are extracting.

Look in the PR for reference

#### B. Extractor Logic (`[EXTRACTOR_NAME].go`)

Look in the PR for reference


#### C. Tests (`[EXTRACTOR_NAME]_test.go` and `metadata/metadata_test.go`)

Look in the PR for reference

### Step 2.2: Update Existing Framework Files

Forgetting these steps is the most common reason a new extractor doesn't run.

#### A. Protobuf Definition (`binary/proto/scan_result.proto`)

*   **Action:** Add a new `message` for your extractor's metadata and add it to the `oneof metadata` block in the `Package` message. **You must pick unique integer IDs.**

```proto
message Package {
  // ...
  oneof metadata {
    // ...
    [EXTRACTOR_NAME]Metadata [EXTRACTOR_NAME]_metadata = 56; // Choose a unique ID
  }
}

message [EXTRACTOR_NAME]Metadata {
  // Add fields for your metadata here
}
```

#### B. Protobuf Go Generation

*   **Action:** After updating the `.proto` file, run the following command to regenerate the Go code:

```bash
make protos
```

#### C. Extractor Registration (`extractor/filesystem/list/list.go`)

*   **Action:** Add your new package to the `import` block and then add your extractor to the `All` map initialization.

#### D. Protobuf Conversion (`binary/proto/package_metadata.go`)

*   **Action:** Add a new case to the `switch` statement in the `ToProto` and `FromProto` functions to handle the new metadata type.

## Part 3: Final Steps & Troubleshooting

1.  **Run Tests:** Run all tests to ensure your changes didn't break anything: `make test`

### Building the `scalibr` binary

To build the `scalibr` binary, run the following commands from the root of the project:

```bash
make clean
make protos
make scalibr
```

> ### Common Pitfalls
> *   **Extractor not running?** Did you register it in `extractor/filesystem/list/list.go`?
> *   **Build errors after changing `scan_result.proto`?** Did you run `make protos`?
> *   **Incorrect data extracted?** Check your parsing logic and regexes.
> *   **Tests failing?** Make sure you have created appropriate test cases, including positive and negative cases.