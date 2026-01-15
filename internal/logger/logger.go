package logger

import (
	"context"
	"log/slog"
	"os"
)

type contextKey string

const (
	RequestIDKey    contextKey = "request_id"
	AWSRequestIDKey contextKey = "aws_request_id"
	FunctionARNKey  contextKey = "function_arn"
	SourceIPKey     contextKey = "source_ip"
	SubjectKey      contextKey = "subject"
)

var defautLogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func Info(ctx context.Context, msg string, attrs ...any) {
	attrs = appendContextAttrs(ctx, attrs)
	defautLogger.InfoContext(ctx, msg, attrs...)
}

func Error(ctx context.Context, msg string, attrs ...any) {
	attrs = appendContextAttrs(ctx, attrs)
	defautLogger.ErrorContext(ctx, msg, attrs...)
}

func Debug(ctx context.Context, msg string, attrs ...any) {
	attrs = appendContextAttrs(ctx, attrs)
	defautLogger.DebugContext(ctx, msg, attrs...)
}

func appendContextAttrs(ctx context.Context, attrs []any) []any {
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok {
		attrs = append(attrs, slog.String("request_id", reqID))
	}
	if awsReqID, ok := ctx.Value(AWSRequestIDKey).(string); ok {
		attrs = append(attrs, slog.String("aws_request_id", awsReqID))
	}
	if functionARN, ok := ctx.Value(FunctionARNKey).(string); ok {
		attrs = append(attrs, slog.String("function_arn", functionARN))
	}
	if sourceIP, ok := ctx.Value(SourceIPKey).(string); ok {
		attrs = append(attrs, slog.String("source_ip", sourceIP))
	}
	if subject, ok := ctx.Value(SubjectKey).(string); ok {
		attrs = append(attrs, slog.String("subject", subject))
	}
	return attrs
}
