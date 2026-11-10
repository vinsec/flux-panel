package panel

import "testing"

func TestReconcileRemovesAdvancedPolicyOnSchemaDowngrade(t *testing.T) {
	for _, oldSchema := range []int64{3, 4, 5} {
		desired := M{"schemaVersion": int64(2), "listenIP": "0.0.0.0", "listenPort": int64(18000), "targetIP": "192.0.2.1", "targetPort": int64(19000), "enabled": true}
		actual := M{}
		for k, v := range desired {
			actual[k] = v
		}
		actual["schemaVersion"] = oldSchema
		actual["protocolFilter"] = M{"http": true, "tls": true, "socks": true, "unknown": "allow"}
		if !specChanged(desired, actual) {
			t.Fatalf("schema %d retained removed policy", oldSchema)
		}
		delete(actual, "protocolFilter")
		actual["schemaVersion"] = int64(0)
		if specChanged(desired, actual) {
			t.Fatal("converged simple rule keeps reconciling")
		}
	}
}

func TestSimpleWireSchemasConvergeWithAgentCanonicalState(t *testing.T) {
	for _, desiredSchema := range []int64{0, 1, 2} {
		for _, actualSchema := range []int64{0, 1, 2} {
			d := M{"schemaVersion": desiredSchema, "listenIP": "0.0.0.0", "listenPort": int64(18000), "targetIP": "192.0.2.1", "targetPort": int64(19000), "enabled": true}
			a := M{}
			for k, v := range d {
				a[k] = v
			}
			a["schemaVersion"] = actualSchema
			if specChanged(d, a) {
				t.Fatalf("equivalent simple schemas %d/%d repeatedly reconcile", desiredSchema, actualSchema)
			}
			a["targetPort"] = int64(19001)
			if !specChanged(d, a) {
				t.Fatal("canonicalization hid a real target change")
			}
		}
	}
}
