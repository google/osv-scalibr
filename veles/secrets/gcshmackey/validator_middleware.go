package gcshmackey

import (
	"context"
	"fmt"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// patchForGCS modifies the request to make it compatible with GCS
//
// by reverting 2 breaking changes added in aws-sdk-go-v2:
// - it removes the Accept-Encoding header: see https://github.com/aws/aws-sdk-go-v2/issues/1816
// - it remove the x-id query parameter (which if left results in an InvalidArgument error from GCS)
func patchForGCS() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"patchForGCS",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, &v4.SigningError{Err: fmt.Errorf("(patchForGCS) unexpected request middleware type %T", in.Request)}
			}
			req.Header.Del("Accept-Encoding")
			vals := req.URL.Query()
			vals.Del("x-id")
			req.URL.RawQuery = vals.Encode()
			return next.HandleFinalize(ctx, in)
		},
	)
}

var patchForGCSOpt = s3.WithAPIOptions(func(stack *middleware.Stack) error {
	return stack.Finalize.Insert(patchForGCS(), "Signing", middleware.Before)
})
