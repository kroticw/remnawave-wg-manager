package main

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(env(map[string]string{"PANEL_URL": "http://remnawave:3000"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.BasePath != "/wg" || c.LoginPath != "/auth/login" || c.MTU != 1380 || c.SubnetPrefix != 24 ||
		c.DNS != "1.1.1.1, 8.8.8.8" || c.Listen != ":8080" || !c.Forwarded {
		t.Fatalf("defaults %+v", c)
	}
}

func TestLoadConfigRequiresPanelURL(t *testing.T) {
	if _, err := loadConfig(env(nil)); err == nil {
		t.Fatal("PANEL_URL must be required")
	}
}

func TestLoadConfigRejectsBadNumbers(t *testing.T) {
	for _, kv := range [][2]string{{"CLIENT_MTU", "abc"}, {"SUBNET_PREFIX", "40"}, {"CLIENT_MTU", "100"}} {
		if _, err := loadConfig(env(map[string]string{"PANEL_URL": "http://x", kv[0]: kv[1]})); err == nil {
			t.Errorf("%s=%s must be rejected", kv[0], kv[1])
		}
	}
}
