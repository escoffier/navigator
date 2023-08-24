package waf

// func TestGeneratePluginConfig(t *testing.T) {
// 	type args struct {
// 		config *Config
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want *structpb.Struct
// 	}{
// 		{
// 			name: "test1",
// 			args: args{
// 				config: &Config{
// 					Mode: "protect",
// 					Rules: []*Rule{
// 						{
// 							ID:          0,
// 							Description: "test rule 0",
// 						},
// 					},
// 					Log: LogConfig{
// 						Enable: 1,
// 						Level:  "debug",
// 					},
// 				},
// 			},
// 			want: &structpb.Struct{
// 				Fields: map[string]*structpb.Value{
// 					"mode": structpb.NewStringValue("protect"),
// 					"log": structpb.NewStructValue(&structpb.Struct{
// 						Fields: map[string]*structpb.Value{
// 							"enable": structpb.NewNumberValue(float64(1)),
// 							"level":  structpb.NewStringValue("debug"),
// 						},
// 					}),
// 					"rules": structpb.NewListValue(&structpb.ListValue{
// 						Values: []*structpb.Value{
// 							structpb.NewStructValue(&structpb.Struct{
// 								Fields: map[string]*structpb.Value{
// 									"id":          structpb.NewNumberValue(float64(0)),
// 									"level":       structpb.NewNumberValue(float64(0)),
// 									"scope":       structpb.NewStringValue(""),
// 									"description": structpb.NewStringValue("test rule 0"),
// 									"expr":        structpb.NewStringValue(""),
// 									"mode":        structpb.NewStringValue(""),
// 								},
// 							}),
// 						},
// 					}),
// 				},
// 			},
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got, err := GeneratePluginConfig(tt.args.config); err != nil || !reflect.DeepEqual(got, tt.want) {
// 				data, err := got.MarshalJSON()
// 				if err == nil {
// 					t.Errorf("marshal json err: %v", string(data))
// 				}
// 				t.Errorf("err: %v, GeneratePluginConfig() = %v, want %v", err, got.String(), tt.want.String())
// 			}
// 		})
// 	}
// }
