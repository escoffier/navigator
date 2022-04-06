package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
)

func TestCron(t *testing.T) {
	var testDatas = []struct {
		cron   *scap.Cron
		valid  bool
		except string
	}{
		{
			cron: &scap.Cron{
				Type: 1,
				Time: "",
			},
			valid:  true,
			except: "",
		},

		{
			cron: &scap.Cron{
				Type: 1,
				Time: "qweq",
			},
			valid:  true,
			except: "",
		},

		{
			cron: &scap.Cron{
				Type: 2,
				Time: "00:11:22",
			},
			valid:  true,
			except: "22 11 00 * * *",
		},

		{
			cron: &scap.Cron{
				Type: 3,
				Time: "2/00:11:22",
			},
			valid:  true,
			except: "22 11 00 * * 2",
		},

		{
			cron: &scap.Cron{
				Type: 4,
				Time: "02/00:11:22",
			},
			valid:  true,
			except: "22 11 00 02 * *",
		},

		{
			cron: &scap.Cron{
				Type: 5,
				Time: "03/02/00:11:22",
			},
			valid:  true,
			except: "22 11 00 02 03 *",
		},
		{
			cron: &scap.Cron{
				Type: 2,
				Time: "1:1:2",
			},
			valid:  true,
			except: "2 1 1 * * *",
		},

		{
			cron: &scap.Cron{
				Type: 3,
				Time: "2/1:11:22",
			},
			valid:  true,
			except: "22 11 1 * * 2",
		},

		{
			cron: &scap.Cron{
				Type: 4,
				Time: "3/0:11:2",
			},
			valid:  true,
			except: "2 11 0 3 * *",
		},

		{
			cron: &scap.Cron{
				Type: 5,
				Time: "3/2/00:9:22",
			},
			valid:  true,
			except: "22 9 00 2 3 *",
		},
	}

	for _, v := range testDatas {
		cron, err := Cron(v.cron)
		if !v.valid {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, cron, v.except)
		}
	}
}

func TestParseCron(t *testing.T) {
	var testDatas = []struct {
		except *scap.Cron
		cron   string
	}{
		{
			except: &scap.Cron{
				Type: 1,
				Time: "",
			},
			cron: "",
		},

		{
			except: &scap.Cron{
				Type: 2,
				Time: "00:11:22",
			},
			cron: "22 11 00 * * *",
		},

		{
			except: &scap.Cron{
				Type: 3,
				Time: "2/00:11:22",
			},
			cron: "22 11 00 * * 2",
		},

		{
			except: &scap.Cron{
				Type: 4,
				Time: "02/00:11:22",
			},
			cron: "22 11 00 02 * *",
		},

		{
			except: &scap.Cron{
				Type: 5,
				Time: "03/02/00:11:22",
			},
			cron: "22 11 00 02 03 *",
		},
	}

	for _, v := range testDatas {
		c := ParseCron(v.cron)
		assert.Equal(t, c.Type, v.except.Type)
		assert.Equal(t, c.Time, v.except.Time)
	}
}
