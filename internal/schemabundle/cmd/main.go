package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/prappser/prappser-spaces/internal/schemabundle"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "build" {
		fmt.Fprintln(os.Stderr, "usage: schemabundle build [-schemas dir] [-previous file] [-out file] [-dry-run]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	var o schemabundle.Options
	fs.StringVar(&o.SchemasDir, "schemas", "internal/component/schemas", "schemas directory")
	fs.StringVar(&o.PreviousPath, "previous", "", "previously published bundle (optional)")
	fs.StringVar(&o.OutPath, "out", "", "output path (default: the embedded signed/ dir, or a temp file with -dry-run)")
	fs.BoolVar(&o.DryRun, "dry-run", false, "sign with a throwaway key")
	_ = fs.Parse(os.Args[2:])
	o.KeyB64 = os.Getenv("SCHEMA_SIGNING_KEY")
	var err error
	if o.OutPath, err = schemabundle.ResolveOutPath(o.OutPath, o.DryRun); err != nil {
		fmt.Fprintln(os.Stderr, "schemabundle:", err)
		os.Exit(1)
	}

	res, err := schemabundle.Execute(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "schemabundle:", err)
		os.Exit(1)
	}
	if res.Warning != "" {
		fmt.Println("::warning::" + res.Warning)
	}
	fmt.Fprintf(os.Stderr, "schemabundle: action=%s bundle=%d\n", res.Action, res.Bundle)
	if p := os.Getenv("GITHUB_OUTPUT"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "schemabundle:", err)
			os.Exit(1)
		}
		fmt.Fprintf(f, "action=%s\nbundle=%d\n", res.Action, res.Bundle)
		f.Close()
	}
}
