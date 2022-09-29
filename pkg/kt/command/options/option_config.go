package options

import (
	"github.com/alibaba/kt-connect/pkg/kt/util"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"reflect"
	"unsafe"
)

type OptionConfig struct {
	Target       string
	Alias        string
	DefaultValue any
	Description  string
	Hidden       bool
	Required     bool
}

func SetOptions(cmd *cobra.Command, flags *flag.FlagSet, optionStore any, config []OptionConfig) {
	cmd.Long = cmd.Short
	cmd.Flags().SortFlags = false
	cmd.InheritedFlags().SortFlags = false
	flags.SortFlags = false
	/*
		config的形式如下:
		[
			{
				Target:      "Mode",
		        DefaultValue: "tun2socks",
				Description: "Connect mode 'tun2socks' or 'sshuttle'",
			},
			{
				Target:      "DnsMode",
				DefaultValue: "localDNS",
				Description: "Specify how to resolve service domains, can be 'localDNS', 'podDNS', 'hosts' or 'hosts:<namespaces>', for multiple namespaces use ',' separation",
			},
		]
	*/
	for _, c := range config {
		// DnsMode
		name := util.UnCapitalize(c.Target)                                // => dnsMode
		field := reflect.ValueOf(optionStore).Elem().FieldByName(c.Target) // => 根据DnsMode索引到对应的field字段
		switch c.DefaultValue.(type) {                                     // DefaultValue 只支持三种形式 string、boolean、int
		case string:
			fieldPtr := (*string)(unsafe.Pointer(field.UnsafeAddr()))
			defaultValue := c.DefaultValue.(string)
			if field.String() != "" {
				defaultValue = field.String()
			}
			if c.Alias != "" {
				flags.StringVarP(fieldPtr, name, c.Alias, defaultValue, c.Description)
			} else {
				flags.StringVar(fieldPtr, name, defaultValue, c.Description)
			}
		case int:
			defaultValue := c.DefaultValue.(int)
			if field.Int() != 0 {
				defaultValue = int(field.Int())
			}
			fieldPtr := (*int)(unsafe.Pointer(field.UnsafeAddr()))
			if c.Alias != "" {
				flags.IntVarP(fieldPtr, name, c.Alias, defaultValue, c.Description)
			} else {
				flags.IntVar(fieldPtr, name, defaultValue, c.Description)
			}
		case bool:
			defaultValue := c.DefaultValue.(bool)
			if field.Bool() {
				defaultValue = field.Bool()
			}
			fieldPtr := (*bool)(unsafe.Pointer(field.UnsafeAddr()))
			if c.Alias != "" {
				flags.BoolVarP(fieldPtr, name, c.Alias, defaultValue, c.Description)
			} else {
				flags.BoolVar(fieldPtr, name, defaultValue, c.Description)
			}
		}
		if c.Hidden {
			_ = flags.MarkHidden(name)
		}
		if c.Required {
			_ = cmd.MarkFlagRequired(name)
		}
	}
}
