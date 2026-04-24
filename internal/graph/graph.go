// Package graph provides dependency graph visualization and analysis.
package graph

import (
	"fmt"
	"sort"
	"strings"
)

// Node represents a package in the dependency graph.
type Node struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	VulnCount   int      `json:"vuln_count"`
	CriticalVuln int     `json:"critical_vuln"`
	HighVuln    int      `json:"high_vuln"`
	Licenses    []string `json:"licenses"`
	RiskScore   float64  `json:"risk_score"`
}

// Edge represents a dependency relationship.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"` // "direct", "transitive"
}

// Graph represents a dependency graph.
type Graph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []Edge           `json:"edges"`
}

// NewGraph creates a new empty graph.
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: []Edge{},
	}
}

// AddNode adds a node to the graph.
func (g *Graph) AddNode(id, name, version string) {
	if _, exists := g.Nodes[id]; !exists {
		g.Nodes[id] = &Node{
			ID:       id,
			Name:     name,
			Version:  version,
			Licenses: []string{},
		}
	}
}

// AddEdge adds an edge to the graph.
func (g *Graph) AddEdge(from, to, edgeType string) {
	g.Edges = append(g.Edges, Edge{
		From: from,
		To:   to,
		Type: edgeType,
	})
}

// UpdateVulnerabilities updates vulnerability counts for a node.
func (g *Graph) UpdateVulnerabilities(id string, critical, high, total int) {
	if node, exists := g.Nodes[id]; exists {
		node.CriticalVuln = critical
		node.HighVuln = high
		node.VulnCount = total
	}
}

// UpdateRiskScore updates the risk score for a node.
func (g *Graph) UpdateRiskScore(id string, score float64) {
	if node, exists := g.Nodes[id]; exists {
		node.RiskScore = score
	}
}

// GetCriticalPath finds the path from root to most critical vulnerable package.
func (g *Graph) GetCriticalPath(root string) []string {
	// Find node with highest risk score
	maxRisk := -1.0
	criticalNode := ""

	for id, node := range g.Nodes {
		if node.RiskScore > maxRisk {
			maxRisk = node.RiskScore
			criticalNode = id
		}
	}

	if criticalNode == "" {
		return []string{}
	}

	// BFS to find path from root to critical node
	visited := make(map[string]bool)
	parent := make(map[string]string)
	queue := []string{root}
	visited[root] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == criticalNode {
			// Reconstruct path
			path := []string{criticalNode}
			for p, ok := parent[current]; ok; p, ok = parent[p] {
				path = append([]string{p}, path...)
			}
			return path
		}

		// Explore neighbors
		for _, edge := range g.Edges {
			if edge.From == current && !visited[edge.To] {
				visited[edge.To] = true
				parent[edge.To] = current
				queue = append(queue, edge.To)
			}
		}
	}

	return []string{}
}

// GetVulnerablePackages returns all packages with vulnerabilities, sorted by risk.
func (g *Graph) GetVulnerablePackages() []*Node {
	var vulnerable []*Node
	for _, node := range g.Nodes {
		if node.VulnCount > 0 {
			vulnerable = append(vulnerable, node)
		}
	}

	// Sort by risk score descending
	sort.Slice(vulnerable, func(i, j int) bool {
		return vulnerable[i].RiskScore > vulnerable[j].RiskScore
	})

	return vulnerable
}

// GetDependents returns packages that depend on the given node.
func (g *Graph) GetDependents(nodeID string) []string {
	var dependents []string
	for _, edge := range g.Edges {
		if edge.To == nodeID {
			dependents = append(dependents, edge.From)
		}
	}
	return dependents
}

// ToDot converts the graph to Graphviz DOT format.
func (g *Graph) ToDot() string {
	var b strings.Builder

	b.WriteString("digraph dependencies {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [fontname=\"Arial\", fontsize=10];\n")
	b.WriteString("  edge [fontname=\"Arial\", fontsize=9];\n\n")

	// Define nodes with styling based on vulnerability status
	for _, node := range g.Nodes {
		label := fmt.Sprintf("%s\\n%s", node.Name, node.Version)

		// Color based on vulnerability level
		color := "lightgreen"  // No vulnerabilities
		shape := "box"

		if node.CriticalVuln > 0 {
			color = "red"
			shape = "box3d"
			label += fmt.Sprintf("\\n🔴 %d critical", node.CriticalVuln)
		} else if node.HighVuln > 0 {
			color = "orange"
			label += fmt.Sprintf("\\n🟠 %d high", node.HighVuln)
		} else if node.VulnCount > 0 {
			color = "yellow"
			label += fmt.Sprintf("\\n🟡 %d total", node.VulnCount)
		}

		if node.RiskScore > 0 {
			label += fmt.Sprintf("\\nRisk: %.1f", node.RiskScore)
		}

		b.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\", fillcolor=%s, style=filled, shape=%s];\n",
			node.ID, label, color, shape))
	}

	b.WriteString("\n")

	// Define edges
	for _, edge := range g.Edges {
		style := "solid"
		color := "black"

		if edge.Type == "transitive" {
			style = "dashed"
			color = "gray"
		}

		b.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [style=%s, color=%s];\n",
			edge.From, edge.To, style, color))
	}

	b.WriteString("}\n")

	return b.String()
}

// ToMermaid converts the graph to Mermaid.js format.
func (g *Graph) ToMermaid() string {
	var b strings.Builder

	b.WriteString("graph LR\n")

	// Define nodes
	for _, node := range g.Nodes {
		shape := "["
		style := ""

		if node.CriticalVuln > 0 {
			shape = "{{"
			style = "fill:#ff6b6b,stroke:#c92a2a,stroke-width:2px"
		} else if node.HighVuln > 0 {
			shape = "("
			style = "fill:#ffd43b,stroke:#fab005"
		} else if node.VulnCount > 0 {
			shape = "("
			style = "fill:#ffe3e3,stroke:#ff8787"
		}

		label := fmt.Sprintf("%s@%s", node.Name, node.Version)
		if node.VulnCount > 0 {
			label += fmt.Sprintf("\\n(%d vulns)", node.VulnCount)
		}

		if style != "" {
			b.WriteString(fmt.Sprintf("  %s%s%s[\"%s\"]%s\n", node.ID, shape, shape, label, shape))
			b.WriteString(fmt.Sprintf("  style %s %s\n", node.ID, style))
		} else {
			b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", node.ID, label))
		}
	}

	// Define edges
	for _, edge := range g.Edges {
		if edge.Type == "transitive" {
			b.WriteString(fmt.Sprintf("  %s -.-> %s\n", edge.From, edge.To))
		} else {
			b.WriteString(fmt.Sprintf("  %s --> %s\n", edge.From, edge.To))
		}
	}

	return b.String()
}

// GenerateASCII generates an ASCII representation of the graph.
func (g *Graph) GenerateASCII() string {
	var b strings.Builder

	b.WriteString("Dependency Graph (Top Vulnerable Packages)\n")
	b.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	vulnerable := g.GetVulnerablePackages()
	if len(vulnerable) == 0 {
		b.WriteString("No vulnerable packages found.\n")
		return b.String()
	}

	for i, node := range vulnerable {
		if i >= 10 { // Show top 10
			break
		}

		riskIndicator := "🟢"
		if node.CriticalVuln > 0 {
			riskIndicator = "🔴"
		} else if node.HighVuln > 0 {
			riskIndicator = "🟠"
		} else if node.RiskScore > 0.5 {
			riskIndicator = "🟡"
		}

		b.WriteString(fmt.Sprintf("%s %s @ %s\n", riskIndicator, node.Name, node.Version))
		b.WriteString(fmt.Sprintf("   Risk Score: %.2f | Vulns: %d (C:%d, H:%d)\n",
			node.RiskScore, node.VulnCount, node.CriticalVuln, node.HighVuln))

		// Show dependents
		dependents := g.GetDependents(node.ID)
		if len(dependents) > 0 {
			b.WriteString("   Required by: ")
			for j, dep := range dependents {
				if j > 0 {
					b.WriteString(", ")
				}
				b.WriteString(dep)
				if j >= 2 && len(dependents) > 3 {
					b.WriteString(fmt.Sprintf(" (+%d more)", len(dependents)-j-1))
					break
				}
			}
			b.WriteString("\n")
		}

		// Show licenses if any
		if len(node.Licenses) > 0 {
			b.WriteString("   License: ")
			b.WriteString(strings.Join(node.Licenses, ", "))
			b.WriteString("\n")
		}

		b.WriteString("\n")
	}

	return b.String()
}

// GetStatistics returns statistics about the graph.
func (g *Graph) GetStatistics() map[string]interface{} {
	totalNodes := len(g.Nodes)
	totalEdges := len(g.Edges)

	totalVulns := 0
	criticalVulns := 0
	highVulns := 0
	vulnPackages := 0

	maxRisk := 0.0
	avgRisk := 0.0

	for _, node := range g.Nodes {
		totalVulns += node.VulnCount
		criticalVulns += node.CriticalVuln
		highVulns += node.HighVuln

		if node.VulnCount > 0 {
			vulnPackages++
		}

		if node.RiskScore > maxRisk {
			maxRisk = node.RiskScore
		}

		avgRisk += node.RiskScore
	}

	if totalNodes > 0 {
		avgRisk /= float64(totalNodes)
	}

	directEdges := 0
	transitiveEdges := 0
	for _, edge := range g.Edges {
		if edge.Type == "direct" {
			directEdges++
		} else {
			transitiveEdges++
		}
	}

	return map[string]interface{}{
		"total_packages":     totalNodes,
		"total_dependencies": totalEdges,
		"direct_dependencies": directEdges,
		"transitive_dependencies": transitiveEdges,
		"vulnerable_packages": vulnPackages,
		"total_vulnerabilities": totalVulns,
		"critical_vulnerabilities": criticalVulns,
		"high_vulnerabilities":    highVulns,
		"max_risk_score":         maxRisk,
		"avg_risk_score":         avgRisk,
		"vulnerability_density":  float64(vulnPackages) / float64(totalNodes),
	}
}
