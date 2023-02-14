package attck

import (
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func TestIsRuleIgnored(t *testing.T) {
	type args struct {
		rule          model.RuleFromYaml
		displayedTags map[string]struct{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "1",
			args: args{
				rule: model.RuleFromYaml{
					Tags: []string{"4t", "xy"},
				},
				displayedTags: map[string]struct{}{"xy": {}},
			},
			want: false,
		},
		{
			name: "2",
			args: args{
				rule: model.RuleFromYaml{
					Tags: []string{"xy"},
				},
				displayedTags: map[string]struct{}{"xy": {}},
			},
			want: false,
		},
		{
			name: "3",
			args: args{
				rule: model.RuleFromYaml{
					Tags: []string{"4t"},
				},
				displayedTags: map[string]struct{}{"xy": {}},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRule4PocIgnored(tt.args.rule, tt.args.displayedTags); got != tt.want {
				t.Errorf("IsRuleIgnored() = %v, want %v", got, tt.want)
			}
		})
	}
}
