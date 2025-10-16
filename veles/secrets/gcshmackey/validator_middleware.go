package gcshmackey

import (
	"context"
	"fmt"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	"github.com/aws/smithy-go/transport/http"
)

func ignoreAcceptEncoding() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"IgnoreHeaders",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
			req, ok := in.Request.(*http.Request)
			if !ok {
				return out, metadata, &v4.SigningError{Err: fmt.Errorf("(ignoreHeaders) unexpected request middleware type %T", in.Request)}
			}
			req.Header.Del("Accept-Encoding")
			return next.HandleFinalize(ctx, in)
		},
	)
}

var ignoreAcceptEncodingOpt = s3.WithAPIOptions(func(stack *middleware.Stack) error {
	return stack.Finalize.Insert(ignoreAcceptEncoding(), "Signing", middleware.Before)
})
