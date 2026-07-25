resource "aws_s3_bucket" "public_fixture" {
  bucket = "reporook-intentionally-insecure-fixture"
  acl    = "public-read"
}
