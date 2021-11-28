package main

type CmdOpts struct {
	Address  string `long:"addr" description:"Radius server address in form address:port" required:"true"`
	User     string `short:"u" description:"Username" required:"true"`
	Password string `short:"p" description:"Password" required:"true"`
	Proto    string `long:"proto" description:"Protocol. Possible values: pap, mschapv2" required:"true"`
	Secret   string `short:"s" description:"Radius secret" required:"true"`
	NASID    string `long:"nid" description:"Nas Id. String"`
	NASPort  uint32 `long:"np" description:"NAS Port" default:"443"`
}
