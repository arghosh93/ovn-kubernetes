// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package sbdb

import "github.com/ovn-kubernetes/libovsdb/model"

const BFDTable = "BFD"

type (
	BFDStatus = string
)

var (
	BFDStatusDown      BFDStatus = "down"
	BFDStatusInit      BFDStatus = "init"
	BFDStatusUp        BFDStatus = "up"
	BFDStatusAdminDown BFDStatus = "admin_down"
)

// BFD defines an object in BFD table
type BFD struct {
	UUID        string            `ovsdb:"_uuid"`
	ChassisName string            `ovsdb:"chassis_name"`
	DetectMult  int               `ovsdb:"detect_mult"`
	Disc        int               `ovsdb:"disc"`
	DstIP       string            `ovsdb:"dst_ip"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	LogicalPort string            `ovsdb:"logical_port"`
	MinRx       int               `ovsdb:"min_rx"`
	MinTx       int               `ovsdb:"min_tx"`
	Options     map[string]string `ovsdb:"options"`
	SrcPort     int               `ovsdb:"src_port"`
	Status      BFDStatus         `ovsdb:"status"`
}

func (a *BFD) GetUUID() string {
	return a.UUID
}

func (a *BFD) GetChassisName() string {
	return a.ChassisName
}

func (a *BFD) GetDetectMult() int {
	return a.DetectMult
}

func (a *BFD) GetDisc() int {
	return a.Disc
}

func (a *BFD) GetDstIP() string {
	return a.DstIP
}

func (a *BFD) GetExternalIDs() map[string]string {
	return a.ExternalIDs
}

func copyBFDExternalIDs(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalBFDExternalIDs(a, b map[string]string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func (a *BFD) GetLogicalPort() string {
	return a.LogicalPort
}

func (a *BFD) GetMinRx() int {
	return a.MinRx
}

func (a *BFD) GetMinTx() int {
	return a.MinTx
}

func (a *BFD) GetOptions() map[string]string {
	return a.Options
}

func copyBFDOptions(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalBFDOptions(a, b map[string]string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func (a *BFD) GetSrcPort() int {
	return a.SrcPort
}

func (a *BFD) GetStatus() BFDStatus {
	return a.Status
}

func (a *BFD) DeepCopyInto(b *BFD) {
	*b = *a
	b.ExternalIDs = copyBFDExternalIDs(a.ExternalIDs)
	b.Options = copyBFDOptions(a.Options)
}

func (a *BFD) DeepCopy() *BFD {
	b := new(BFD)
	a.DeepCopyInto(b)
	return b
}

func (a *BFD) CloneModelInto(b model.Model) {
	c := b.(*BFD)
	a.DeepCopyInto(c)
}

func (a *BFD) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *BFD) Equals(b *BFD) bool {
	return a.UUID == b.UUID &&
		a.ChassisName == b.ChassisName &&
		a.DetectMult == b.DetectMult &&
		a.Disc == b.Disc &&
		a.DstIP == b.DstIP &&
		equalBFDExternalIDs(a.ExternalIDs, b.ExternalIDs) &&
		a.LogicalPort == b.LogicalPort &&
		a.MinRx == b.MinRx &&
		a.MinTx == b.MinTx &&
		equalBFDOptions(a.Options, b.Options) &&
		a.SrcPort == b.SrcPort &&
		a.Status == b.Status
}

func (a *BFD) EqualsModel(b model.Model) bool {
	c := b.(*BFD)
	return a.Equals(c)
}

var _ model.CloneableModel = &BFD{}
var _ model.ComparableModel = &BFD{}
