package gpo

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type BloodHoundNode struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
}

type BloodHoundEdge struct {
	SourceType string                 `json:"sourceType"`
	Source     string                 `json:"source"`
	TargetType string                 `json:"targetType"`
	Target     string                 `json:"target"`
	Properties map[string]interface{} `json:"properties"`
}

type BloodHoundData struct {
	Nodes []BloodHoundNode `json:"nodes"`
	Edges []BloodHoundEdge `json:"edges"`
}

type GPOBloodHoundResult struct {
	GPOName           string
	GPOGUID           string
	AffectedUsers     []string
	AffectedComputers []string
	WritableBy        []string
	AttackPaths       []string
}

func ExportGPOsToBloodHound(gpos []GPO, outputPath string) error {
	var nodes []BloodHoundNode
	var edges []BloodHoundEdge

	for _, gpo := range gpos {
		node := BloodHoundNode{
			Type: "GroupPolicyObject",
			Properties: map[string]interface{}{
				"name":            gpo.Name,
				"objectid":        gpo.GUID,
				"domainsid":       "",
				"functionallevel": gpo.FuncVersion,
				"version":         gpo.Version,
				"computers":       len(gpo.Links) > 0,
				"users":           gpo.UserEnabled,
				"gpcpath":         gpo.FileSysPath,
			},
		}
		nodes = append(nodes, node)

		for _, link := range gpo.Links {
			edge := BloodHoundEdge{
				SourceType: "GroupPolicyObject",
				Source:     gpo.GUID,
				TargetType: "OU",
				Target:     link.TargetDN,
				Properties: map[string]interface{}{
					"isacl":       false,
					"iscontainer": true,
					"right":       "GpLink",
					"ison":        link.Enabled,
				},
			}
			edges = append(edges, edge)
		}

		if gpo.ACL != nil && gpo.ACL.DACL != nil {
			for _, ace := range gpo.ACL.DACL.ACEs {
				if ace.Type == ACETypeAccessAllowed {
					for _, right := range ace.Rights {
						if right == "GenericAll" || right == "GenericWrite" || right == "WriteDACL" {
							edge := BloodHoundEdge{
								SourceType: "User",
								Source:     ace.SIDText,
								TargetType: "GroupPolicyObject",
								Target:     gpo.GUID,
								Properties: map[string]interface{}{
									"isacl":       true,
									"right":       right,
									"ison":        true,
									"isinherited": false,
								},
							}
							edges = append(edges, edge)
						}
					}
				}
			}
		}
	}

	data := BloodHoundData{
		Nodes: nodes,
		Edges: edges,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal BloodHound data: %w", err)
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}

func AnalyzeGPOAttackPaths(gpos []GPO) []AttackPath {
	var paths []AttackPath

	for _, gpo := range gpos {
		if !gpo.HasWritableACL() {
			continue
		}

		path := AttackPath{
			ID:   gpo.GUID,
			Name: fmt.Sprintf("GPO Control: %s", gpo.Name),
			Steps: []AttackStep{
				{
					Action:      "Gain control of GPO",
					Target:      gpo.Name,
					Description: fmt.Sprintf("Write access to GPO %s", gpo.Name),
					Tool:        "trusted gpo --acl",
				},
				{
					Action:      "Modify GPO configuration",
					Target:      gpo.Name,
					Description: "Add malicious task, script, or registry setting",
					Tool:        "trusted gpo --exploit",
				},
				{
					Action:      "Wait for GPO application",
					Target:      "Target computers",
					Description: "Run gpupdate /force or wait for next refresh cycle",
					Tool:        "Manual",
				},
			},
			Risk:        "HIGH",
			Description: fmt.Sprintf("Writable GPO %s can be modified to execute code on all linked computers", gpo.Name),
		}
		paths = append(paths, path)

		if gpo.IsLinkedToDC() {
			dcPath := AttackPath{
				ID:   gpo.GUID + "_DC",
				Name: fmt.Sprintf("Domain Controller Compromise: %s", gpo.Name),
				Steps: []AttackStep{
					{
						Action:      "Gain control of GPO linked to DC",
						Target:      gpo.Name,
						Description: fmt.Sprintf("GPO %s is linked to Domain Controllers OU", gpo.Name),
						Tool:        "trusted gpo --acl",
					},
					{
						Action:      "Modify GPO for DC compromise",
						Target:      gpo.Name,
						Description: "Add immediate task or startup script targeting DC",
						Tool:        "trusted gpo --exploit task",
					},
				},
				Risk:        "CRITICAL",
				Description: fmt.Sprintf("GPO %s linked to Domain Controllers OU — modification leads to domain compromise", gpo.Name),
			}
			paths = append(paths, dcPath)
		}
	}

	return paths
}

func ImportBloodHoundJSON(jsonPath string) (*BloodHoundData, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read BloodHound JSON: %w", err)
	}

	var bhData BloodHoundData
	if err := json.Unmarshal(data, &bhData); err != nil {
		return nil, fmt.Errorf("parse BloodHound JSON: %w", err)
	}

	return &bhData, nil
}

func CorrelateGPOsWithBloodHound(gpos []GPO, bhData *BloodHoundData) []GPOBloodHoundResult {
	var results []GPOBloodHoundResult

	for _, gpo := range gpos {
		result := GPOBloodHoundResult{
			GPOName: gpo.Name,
			GPOGUID: gpo.GUID,
		}

		for _, edge := range bhData.Edges {
			if edge.Source == gpo.GUID && edge.SourceType == "GroupPolicyObject" {
				if edge.TargetType == "User" {
					result.AffectedUsers = append(result.AffectedUsers, edge.Target)
				} else if edge.TargetType == "Computer" {
					result.AffectedComputers = append(result.AffectedComputers, edge.Target)
				}
			}

			if edge.Target == gpo.GUID && edge.TargetType == "GroupPolicyObject" {
				if edge.SourceType == "User" {
					right, _ := edge.Properties["right"].(string)
					if right == "GenericAll" || right == "GenericWrite" || right == "WriteDACL" {
						result.WritableBy = append(result.WritableBy, edge.Source)
					}
				}
			}
		}

		if gpo.IsLinkedToDC() {
			result.AttackPaths = append(result.AttackPaths, "Domain Controller compromise via GPO")
		}
		if gpo.HasWritableACL() {
			result.AttackPaths = append(result.AttackPaths, "Direct GPO modification")
		}

		results = append(results, result)
	}

	return results
}

func GenerateBloodHoundCypher(gpos []GPO) string {
	var queries []string

	for _, gpo := range gpos {
		if gpo.HasWritableACL() {
			queries = append(queries, fmt.Sprintf("// Find principals with write access to GPO %s\nMATCH (n)-[:WriteDacl|WriteOwner|GenericAll|GenericWrite]->(g:GroupPolicyObject {objectid: '%s'}) RETURN n, g", gpo.Name, gpo.GUID))
		}

		if gpo.IsLinkedToDC() {
			queries = append(queries, fmt.Sprintf("// Find computers affected by GPO %s linked to DC\nMATCH (g:GroupPolicyObject {objectid: '%s'})-[:GpLink]->(ou:OU)-[:Contains]->(c:Computer) RETURN g, ou, c", gpo.Name, gpo.GUID))
		}
	}

	return fmt.Sprintf("// Trusted GPO Analysis Queries\n// Generated: %s\n\n%s", time.Now().Format("2006-01-02 15:04:05"), joinQueries(queries))
}

func joinQueries(queries []string) string {
	result := ""
	for _, q := range queries {
		result += q + "\n\n"
	}
	return result
}
