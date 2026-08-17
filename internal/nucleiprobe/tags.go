package nucleiprobe

import (
	"sort"
	"strings"
)

// normalizeTag converts a fingerprint label (e.g. "Spring Boot", "ThinkPHP")
// into a nuclei tag token: lowercase, ASCII letters/digits only, other runes
// dropped. nuclei tags are lowercase product names such as "wordpress",
// "spring", "thinkphp", "apache".
func normalizeTag(label string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fingerprintTagAliases maps a normalized fingerprint token to one or more
// nuclei tags. Entries are needed in two cases:
//   - the fingerprint name normalizes to a token that differs from the nuclei
//     tag (e.g. "Spring Boot" also warrants the broader "spring" tag), or
//   - a specific product legitimately maps onto an otherwise-broad tag and the
//     mapping has been human-verified as low false-positive.
//
// Fingerprints not listed here fall back to their normalized token, but only
// when that token is a specific product tag; broad technology tags are dropped
// (see broadTags) to keep the false-positive rate low.
var fingerprintTagAliases = map[string][]string{
	"springboot":               {"spring", "springboot"},
	"springbootactuator":       {"spring", "springboot"},
	"springbootactuatorhealth": {"spring", "springboot"},
	"springbootadmin":          {"spring", "springboot"},
	"springcloud":              {"spring"},
	"springcloudgateway":       {"spring"},
	"springframew":             {"spring"},
	"springsecurity":           {"spring"},
	"apachehttpd":              {"apache"},
	"apachehttpserver":         {"apache"},
	"apache":                   {"apache"},
	"apachetomcat":             {"tomcat"},
	"tomcat":                   {"tomcat"},
	"nginx":                    {"nginx"},
	"iis":                      {"iis"},
	"microsoftiis":             {"iis"},
	"phpmyadmin":               {"phpmyadmin"},
	"thinkphp":                 {"thinkphp"},
	"weblogic":                 {"weblogic"},
	"weblogicconsole":          {"weblogic"},
	"oracleweblog":             {"weblogic"},
	"oracleweblogic":           {"weblogic"},
	"jenkins":                  {"jenkins"},
	"gitlab":                   {"gitlab"},
	"grafana":                  {"grafana"},
	"jira":                     {"jira"},
	"confluence":               {"confluence"},
	"nacos":                    {"nacos"},
	"apachenacos":              {"nacos"},
	"druid":                    {"druid"},
	"elasticsear":              {"elasticsearch"},
	"kibana":                   {"kibana"},
	"solr":                     {"solr"},
	"apachesolr":               {"solr"},
	"harbor":                   {"harbor"},
	"nexus":                    {"nexus"},
	"zabbix":                   {"zabbix"},
	"discuz":                   {"discuz"},
	"dedecms":                  {"dedecms"},
	"metinfo":                  {"metinfo"},
	"seeyon":                   {"seeyon"},
	"seeyonoa":                 {"seeyon"},
	"tongdaoa":                 {"tongda"},
	"yonyou":                   {"yonyou"},
	"yonyounc":                 {"yonyou"},
	"yonyouu8grpu8":            {"yonyou"},
	"kingdee":                  {"kingdee"},
	"k3cloud":                  {"kingdee"},
	"iofficeoa":                {"hongfan"},
	"ecology":                  {"weaver", "ecology"},
	"weaverecology":            {"weaver", "ecology"},
	"oaecology":                {"weaver", "ecology"},
	"weavereoffice":            {"weaver", "eoffice"},
	"emobile":                  {"weaver", "ecology"},
	"weaveremobile":            {"weaver", "ecology"},
	"weaver":                   {"weaver"},
	// Verified specific products whose nuclei tag differs from the raw
	// fingerprint token. Each target tag was confirmed to have non-empty
	// templates in the nuclei ruleset.
	"tplink":        {"tplink"},
	"hikvision":     {"hikvision"},
	"dahua":         {"dahua"},
	"sangfor":       {"sangfor"},
	"sangfordevice": {"sangfor"},
	"ruijiedevice":  {"ruijie"},
	"topsecdevice":  {"topsec"},
	"sapnetweaver":  {"netweaver"},
	"landrayoa":     {"landray"},
	"landray":       {"landray"},
	"jeecgboot":     {"jeecg"},
	"ruoyi":         {"ruoyi"},
	"xxljob":        {"xxljob"},
	"showdoc":       {"showdoc"},
	"metersphere":   {"metersphere"},
	"finereport":    {"finereport"},
	"jumpserver":    {"jumpserver"},
	"gitea":         {"gitea"},
	"gogs":          {"gogs"},
	"keycloak":      {"keycloak"},
	"nagios":        {"nagios"},
	"prometheus":    {"prometheus"},
	"sonarqube":     {"sonarqube"},
	"minio":         {"minio"},
	"rabbitmq":      {"rabbitmq"},
	"laravel":       {"laravel"},
	"django":        {"django"},
	"drupal":        {"drupal"},
	"joomla":        {"joomla"},
	"magento":       {"magento"},
	"wordpress":     {"wordpress"},
}

// broadTags are generic technology/category tags that match a large, mostly
// unrelated set of nuclei templates. A specific product fingerprint that only
// normalizes onto one of these (e.g. "天融信VPN设备" -> "vpn", "网宿-CDN" -> "cdn",
// "悟空CRM" -> "crm") would otherwise trigger a flood of irrelevant POCs, so the
// fallback path drops them. They can still be requested via an explicit alias
// entry above when a mapping has been human-verified.
var broadTags = map[string]struct{}{
	"vpn":       {},
	"cdn":       {},
	"crm":       {},
	"erp":       {},
	"waf":       {},
	"cms":       {},
	"oa":        {},
	"php":       {},
	"java":      {},
	"python":    {},
	"ruby":      {},
	"golang":    {},
	"nodejs":    {},
	"react":     {},
	"aspnet":    {},
	"apache":    {},
	"nginx":     {},
	"iis":       {},
	"router":    {},
	"firewall":  {},
	"camera":    {},
	"iot":       {},
	"panel":     {},
	"tech":      {},
	"ssl":       {},
	"dns":       {},
	"proxy":     {},
	"api":       {},
	"cloud":     {},
	"database":  {},
	"storage":   {},
	"email":     {},
	"login":     {},
	"seo":       {},
	"amazon":    {},
	"google":    {},
	"apple":     {},
	"netflix":   {},
	"dell":      {},
	"huawei":    {},
	"cisco":     {},
	"oracle":    {},
	"microsoft": {},
}

// TagsFor maps a set of recognized fingerprint labels to a de-duplicated,
// sorted list of nuclei tags. Mapping rules, ordered by precedence:
//   - explicit alias entries (fingerprintTagAliases) are always honored, even
//     when they resolve to a broad tag, because they are human-verified;
//   - otherwise the normalized token is used, but only if it is a specific
//     product tag. Tokens that are broad technology categories (broadTags) are
//     dropped to avoid running large, irrelevant template sets against a host.
//
// When no safe tag can be derived the result is empty and the caller should
// skip the origin rather than run nuclei against everything.
func TagsFor(fingerprints []string) []string {
	seen := make(map[string]struct{})
	for _, fp := range fingerprints {
		token := normalizeTag(fp)
		if token == "" {
			continue
		}
		if aliases, ok := fingerprintTagAliases[token]; ok {
			for _, tag := range aliases {
				seen[tag] = struct{}{}
			}
			continue
		}
		if _, broad := broadTags[token]; broad {
			continue
		}
		seen[token] = struct{}{}
	}
	tags := make([]string, 0, len(seen))
	for tag := range seen {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}
