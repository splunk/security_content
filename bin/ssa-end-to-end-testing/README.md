# Running tests

You can run these tests using `pytest`. The required parameters a DSP `token`, the DSP `environment`, and the DSP `tenant`.

## Run all tests in `playground`

```angular2
pytest --env playground --tenant research2 --token <YOUR_DSP_TOKEN>
```

## Run all tests in `staging`

```angular2
pytest --env staging --tenant research --token <YOUR_DSP_TOKEN>
```

## Run specific tests

If you add the argument `-k` to pytest, then it can filter tests to run the tests specified.

```angular2
pytest --env playground --tenant research2 --token <YOUR_DSP_TOKEN> -k test_data_ingestion_preview
```

It also can run tests by category if naming conditions are maintained.

```angular2
pytest --env playground --tenant research2 --token <YOUR_DSP_TOKEN> -k test_data_ingestion
```

Will run tests `test_data_ingestion_preview` and `test_data_ingestion_index`.

## Best Practices

Save your token to an environment variable. Go to *playground* console and copy your token. Then..

```angular2
export SCLOUD_TOKEN_PLAY=$(pbpaste)
```

Go to your *staging* console and copy your token. Then..

```angular2
export SCLOUD_TOKEN_STAGING=$(pbpaste)
```

Now you can easily run tests on both playground, and staging.