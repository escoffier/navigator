package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/producer"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type ValueFromYaml struct {
	V string `yaml:"v"`
}

type FilterFromYaml struct {
	Id        string          `yaml:"id"`
	Field     string          `yaml:"field"`
	Operation string          `yaml:"operation"`
	Values    []ValueFromYaml `yaml:"values"`
}

type ProducerInfoFromYaml struct {
	Name        string           `yaml:"name"`
	Filters     []FilterFromYaml `yaml:"filters"`
	FilterLogic string           `yaml:"logic"`
}

type ProducersInfoFromYaml struct {
	Syscalls []ProducerInfoFromYaml `yaml:"syscalls"`
	Nets     []ProducerInfoFromYaml `yaml:"nets"`
}

type ConfigFromYaml struct {
	Producers ProducersInfoFromYaml `yaml:"producers"`
	Consumers []string              `yaml:"consumers"`
}

func parseProducerInfo(producerType producer.ProducerT, pifYaml *ProducerInfoFromYaml) (producer.ProducerInfoT, error) {
	pif := producer.ProducerInfoT{
		ProducerName:    pifYaml.Name,
		ProducerType:    producerType,
		ProducerFilters: make([]producer.FilterT, 0, len(pifYaml.Filters)),
		FilterLogic:     pifYaml.FilterLogic,
	}
	for _, filterYaml := range pifYaml.Filters {
		if filterYaml.Id != "" {
			log.Infof("Parse %s filter `%s` of [%s]\n", filterYaml.Field, filterYaml.Id, strings.ToUpper(pifYaml.Name))
		} else {
			log.Infof("Parse %s filter of [%s]\n", filterYaml.Field, strings.ToUpper(pifYaml.Name))
		}

		values := make([]string, 0, len(filterYaml.Values))
		for _, valueYaml := range filterYaml.Values {
			values = append(values, valueYaml.V)
		}
		operator, err := yamlStringToFieldOperation(&filterYaml.Operation)
		if err != nil {
			return producer.ProducerInfoT{}, errors.New(fmt.Sprintf("Producer [%s] parse error, because: %v", pifYaml.Name, err))
		}
		pf := producer.FilterT{
			Id:        filterYaml.Id,
			Field:     filterYaml.Field,
			Operation: operator,
			ValueStr:  values,
		}
		pif.ProducerFilters = append(pif.ProducerFilters, pf)
	}
	return pif, nil
}

func ParseYamlFromByte(fData []byte) ([]producer.ProducerInfoT, []producer.ProducerInfoT, []string, error) {
	config := ConfigFromYaml{}

	err := yaml.Unmarshal(fData, &config)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	syscallPIFS := make([]producer.ProducerInfoT, 0, len(config.Producers.Syscalls))
	netPIFS := make([]producer.ProducerInfoT, 0, len(config.Producers.Nets))
	for _, pifYaml := range config.Producers.Syscalls {
		pif, err := parseProducerInfo(producer.Syscall, &pifYaml)
		if err != nil {
			return []producer.ProducerInfoT{}, []producer.ProducerInfoT{}, []string{}, errors.New(fmt.Sprintf("Syscall producer parse error, because: %v", err))
		}
		syscallPIFS = append(syscallPIFS, pif)
	}
	for _, pifYaml := range config.Producers.Nets {
		pif, err := parseProducerInfo(producer.Net, &pifYaml)
		if err != nil {
			return []producer.ProducerInfoT{}, []producer.ProducerInfoT{}, []string{}, errors.New(fmt.Sprintf("Net producer parse error, because: %v", err))
		}
		netPIFS = append(netPIFS, pif)
	}
	return syscallPIFS, netPIFS, config.Consumers, nil
}

func ParseYaml(filename *string) ([]producer.ProducerInfoT, []producer.ProducerInfoT, []string, error) {
	fData, err := ioutil.ReadFile(*filename)
	if err != nil {
		log.Fatalf("Read file %s failed. Error: %s ", *filename, err)
	}

	return ParseYamlFromByte(fData)
}

func yamlStringToFieldOperation(s *string) (producer.FieldOperationT, error) {
	switch *s {
	case "equalTo":
		return producer.FEqualTo, nil
	case "notEqualTo":
		return producer.FNotEqualTo, nil
	case "lessThan":
		return producer.FLessThan, nil
	case "greaterThan":
		return producer.FGreaterThan, nil
	case "equalLessThan":
		return producer.FEqualLessThan, nil
	case "equalGreaterThan":
		return producer.FEqualGreaterThan, nil
	case "startsWith":
		return producer.FStartsWith, nil
	case "notStartsWith":
		return producer.FNotStartsWith, nil
	case "endsWith":
		return producer.FEndsWith, nil
	case "notEndsWith":
		return producer.FNotEndsWith, nil
	case "inArray":
		return producer.FInArray, nil
	case "notInArray":
		return producer.FNotInArray, nil
	case "startsWithArray":
		return producer.FStartsWithArray, nil
	case "notStartsWithArray":
		return producer.FNotStartsWithArray, nil
	case "endsWithArray":
		return producer.FEndsWithArray, nil
	case "notEndsWithArray":
		return producer.FNotEndsWithArray, nil
	case "andIs":
		return producer.FLogicAndIs, nil
	case "andIsNot":
		return producer.FLogicAndIsNot, nil
	case "orIs":
		return producer.FLogicOrIs, nil
	case "orIsNot":
		return producer.FLogicOrIsNot, nil
	case "xorIs":
		return producer.FLogicXorIs, nil
	case "xorIsNot":
		return producer.FLogicXorIsNot, nil
	default:
		return producer.Unknown, errors.New(fmt.Sprintf("Field operator error: %s is not legal operator", *s))
	}
}
