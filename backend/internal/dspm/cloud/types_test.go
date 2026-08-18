package cloud

import "testing"

func TestFindingIDDeterministic(t *testing.T) {
	a := FindingID("aws-s3", "aws", "aws_s3_bucket", "my-bucket", "aws-s3-bucket-encryption")
	b := FindingID("aws-s3", "aws", "aws_s3_bucket", "my-bucket", "aws-s3-bucket-encryption")
	if a != b {
		t.Fatalf("finding ID must be deterministic: %s != %s", a, b)
	}
	if len(a) != 20 {
		t.Fatalf("expected 20-char hex ID, got %d: %s", len(a), a)
	}
}

func TestFindingIDDistinguishesResourceAndRule(t *testing.T) {
	base := FindingID("aws-s3", "aws", "aws_s3_bucket", "my-bucket", "aws-s3-bucket-encryption")
	otherBucket := FindingID("aws-s3", "aws", "aws_s3_bucket", "other-bucket", "aws-s3-bucket-encryption")
	otherRule := FindingID("aws-s3", "aws", "aws_s3_bucket", "my-bucket", "aws-s3-bucket-versioning")
	if base == otherBucket {
		t.Fatal("different resource IDs must yield different finding IDs")
	}
	if base == otherRule {
		t.Fatal("different rule IDs must yield different finding IDs")
	}
}