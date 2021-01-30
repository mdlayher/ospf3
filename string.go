// Code generated by "stringer -type=FloodingScope,LSType -output=string.go"; DO NOT EDIT.

package ospf3

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[LinkLocalScoping-0]
	_ = x[AreaScoping-1]
	_ = x[ASScoping-2]
	_ = x[reservedScoping-3]
}

const _FloodingScope_name = "LinkLocalScopingAreaScopingASScopingreservedScoping"

var _FloodingScope_index = [...]uint8{0, 16, 27, 36, 51}

func (i FloodingScope) String() string {
	if i >= FloodingScope(len(_FloodingScope_index)-1) {
		return "FloodingScope(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _FloodingScope_name[_FloodingScope_index[i]:_FloodingScope_index[i+1]]
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[RouterLSA-8193]
	_ = x[NetworkLSA-8194]
	_ = x[InterAreaPrefixLSA-8195]
	_ = x[InterAreaRouterLSA-8196]
	_ = x[ASExternalLSA-16389]
	_ = x[deprecatedLSA-8198]
	_ = x[NSSALSA-8199]
	_ = x[LinkLSA-8]
	_ = x[IntraAreaPrefixLSA-8201]
}

const (
	_LSType_name_0 = "LinkLSA"
	_LSType_name_1 = "RouterLSANetworkLSAInterAreaPrefixLSAInterAreaRouterLSA"
	_LSType_name_2 = "deprecatedLSANSSALSA"
	_LSType_name_3 = "IntraAreaPrefixLSA"
	_LSType_name_4 = "ASExternalLSA"
)

var (
	_LSType_index_1 = [...]uint8{0, 9, 19, 37, 55}
	_LSType_index_2 = [...]uint8{0, 13, 20}
)

func (i LSType) String() string {
	switch {
	case i == 8:
		return _LSType_name_0
	case 8193 <= i && i <= 8196:
		i -= 8193
		return _LSType_name_1[_LSType_index_1[i]:_LSType_index_1[i+1]]
	case 8198 <= i && i <= 8199:
		i -= 8198
		return _LSType_name_2[_LSType_index_2[i]:_LSType_index_2[i+1]]
	case i == 8201:
		return _LSType_name_3
	case i == 16389:
		return _LSType_name_4
	default:
		return "LSType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
