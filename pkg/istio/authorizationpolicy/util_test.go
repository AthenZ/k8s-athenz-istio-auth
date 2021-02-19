package authzpolicy

import (
	"testing"
)

func TestParseComponentsEnabledAuthzPolicy(t *testing.T) {
	type inputData struct {
		description string
		objectList  string
	}
	type outputData struct {
		result *ComponentEnabled
		err    string
	}
	type testData struct {
		input  inputData
		output outputData
	}
	tests := []testData{
		{
			input: inputData{
				description: "Parse services-enabled-authzpolicy list",
				objectList:  "namespace1/service1,namespace2/service2",
			},
			output: outputData{
				result: &ComponentEnabled{
					serviceList: []ServiceEnabled{
						{
							service:   "service1",
							namespace: "namespace1",
						},
						{
							service:   "service2",
							namespace: "namespace2",
						},
					},
					namespaceList: []string{},
					cluster:       false,
				},
				err: "",
			},
		}, {
			input: inputData{
				description: "Services-enabled-authzpolicy list item has invalid format",
				objectList:  "service1-namespace1,service2-namespace2",
			},
			output: outputData{
				result: nil,
				err:    "Service item service1-namespace1 from command line arg components-enabled-authzpolicy is in incorrect format",
			},
		}, {
			input: inputData{
				description: "Parse namespaces-enabled-authzpolicy list",
				objectList:  "ns1/*,ns2/*,ns3/*",
			},
			output: outputData{
				result: &ComponentEnabled{
					serviceList:   []ServiceEnabled{},
					namespaceList: []string{"ns1", "ns2", "ns3"},
					cluster:       false,
				},
				err: "",
			},
		}, {
			input: inputData{
				description: "Parse clusters-enabled-authzpolicy argument",
				objectList:  "*",
			},
			output: outputData{
				result: &ComponentEnabled{
					serviceList:   []ServiceEnabled{},
					namespaceList: []string{},
					cluster:       true,
				},
				err: "",
			},
		},
	}
	for _, testcase := range tests {
		components, err := ParseComponentsEnabledAuthzPolicy(testcase.input.objectList)
		if err != nil {
			if err.Error() != testcase.output.err {
				t.Errorf("Wrong error message. Expected: %s, Actual: %s", testcase.output.err, err.Error())
			} else {
				continue
			}
		}

		if len(components.serviceList) != len(testcase.output.result.serviceList) {
			t.Error("Object serviceList length mismatch")
		}
		for i := 0; i < len(components.serviceList); i++ {
			if components.serviceList[i].service != testcase.output.result.serviceList[i].service || components.serviceList[i].namespace != testcase.output.result.serviceList[i].namespace {
				t.Error("ServiceEnabled object mismatch")
			}
		}
		if len(components.namespaceList) != len(testcase.output.result.namespaceList) {
			t.Error("Object namespaceList length mismatch")
		}
		for i := 0; i < len(components.namespaceList); i++ {
			if components.namespaceList[i] != testcase.output.result.namespaceList[i] {
				t.Error("Namespace mismatch")
			}
		}
		if components.cluster != testcase.output.result.cluster {
			t.Error("Object cluster value mismatch")
		}
	}

}

func TestIsEnabled(t *testing.T) {
	type inputData struct {
		obj       ComponentEnabled
		service   string
		namespace string
	}
	type testData struct {
		input  inputData
		output bool
	}
	tests := []testData{
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceList: []ServiceEnabled{
						{
							service:   "service1",
							namespace: "namespace1",
						},
						{
							service:   "service2",
							namespace: "namespace2",
						},
					},
					namespaceList: []string{},
					cluster:       false,
				},
				service:   "service1",
				namespace: "namespace1",
			},
			output: true,
		},
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceList:   []ServiceEnabled{},
					namespaceList: []string{"ns1", "ns2", "ns3"},
					cluster:       false,
				},
				service:   "service1",
				namespace: "ns1",
			},
			output: true,
		},
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceList:   []ServiceEnabled{},
					namespaceList: []string{},
					cluster:       true,
				},
				service:   "test",
				namespace: "test",
			},
			output: true,
		},
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceList:   []ServiceEnabled{},
					namespaceList: []string{},
					cluster:       false,
				},
				service:   "service1",
				namespace: "namespace1",
			},
			output: false,
		},
	}
	for index, testcase := range tests {
		if testcase.input.obj.IsEnabled(testcase.input.service, testcase.input.namespace) != testcase.output {
			t.Errorf("Test %d failed, does not match expected output", index)
		}
	}
}
