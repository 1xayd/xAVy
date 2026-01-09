package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"
	"xAVy/analyzer"
)

const (
	InputSize    = 52
	HiddenSize1  = 96
	HiddenSize2  = 48
	OutputSize   = 1
	ModelVersion = 3
)

type RLModel struct {
	W1 [][]float64 // [InputSize][HiddenSize1]
	B1 []float64   // [HiddenSize1]
	W2 [][]float64 // [HiddenSize1][HiddenSize2]
	B2 []float64   // [HiddenSize2]
	W3 []float64   // [HiddenSize2]
	B3 float64

	MW1 [][]float64
	VW1 [][]float64
	MB1 []float64
	VB1 []float64

	MW2 [][]float64
	VW2 [][]float64
	MB2 []float64
	VB2 []float64

	MW3 []float64
	VW3 []float64
	MB3 float64
	VB3 float64

	Step int64

	LearningRate float64
	Beta1        float64
	Beta2        float64
	AdamEps      float64
	WeightDecay  float64
	Dropout      float64
	LeakyAlpha   float64
	GradClip     float64

	NormCount int64
	NormMean  []float64
	NormM2    []float64

	FeatureImportance []float64

	PosCount int64
	NegCount int64

	Stats       ModelStats
	Version     int
	CreatedAt   time.Time
	LastUpdated time.Time
}

type ModelStats struct {
	TrainingSamples      int
	CorrectPredictions   int
	IncorrectPredictions int
	TruePositives        int
	TrueNegatives        int
	FalsePositives       int
	FalseNegatives       int

	LearningRate  float64
	AverageReward float64
	TotalReward   float64

	BestAccuracy float64
	EpochCount   int
}

type ModelData struct {
	W1 [][]float64 `json:"w1"`
	B1 []float64   `json:"b1"`
	W2 [][]float64 `json:"w2"`
	B2 []float64   `json:"b2"`
	W3 []float64   `json:"w3"`
	B3 float64     `json:"b3"`

	MW1 [][]float64 `json:"mw1"`
	VW1 [][]float64 `json:"vw1"`
	MB1 []float64   `json:"mb1"`
	VB1 []float64   `json:"vb1"`

	MW2 [][]float64 `json:"mw2"`
	VW2 [][]float64 `json:"vw2"`
	MB2 []float64   `json:"mb2"`
	VB2 []float64   `json:"vb2"`

	MW3 []float64 `json:"mw3"`
	VW3 []float64 `json:"vw3"`
	MB3 float64   `json:"mb3"`
	VB3 float64   `json:"vb3"`

	Step int64 `json:"step"`

	LearningRate float64 `json:"learning_rate"`
	Beta1        float64 `json:"beta1"`
	Beta2        float64 `json:"beta2"`
	AdamEps      float64 `json:"adam_eps"`
	WeightDecay  float64 `json:"weight_decay"`
	Dropout      float64 `json:"dropout"`
	LeakyAlpha   float64 `json:"leaky_alpha"`
	GradClip     float64 `json:"grad_clip"`

	NormCount int64     `json:"norm_count"`
	NormMean  []float64 `json:"norm_mean"`
	NormM2    []float64 `json:"norm_m2"`

	FeatureImportance []float64 `json:"feature_importance"`

	PosCount int64 `json:"pos_count"`
	NegCount int64 `json:"neg_count"`

	Stats       ModelStats `json:"stats"`
	Version     int        `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUpdated time.Time  `json:"last_updated"`
}

func LoadOrCreateModel(path string) *RLModel {
	if data, err := os.ReadFile(path); err == nil {
		var md ModelData
		if json.Unmarshal(data, &md) == nil && md.Version == ModelVersion {
			fmt.Printf("Loaded existing model (version %d)\n", md.Version)
			return &RLModel{
				W1: md.W1, B1: md.B1,
				W2: md.W2, B2: md.B2,
				W3: md.W3, B3: md.B3,

				MW1: md.MW1, VW1: md.VW1, MB1: md.MB1, VB1: md.VB1,
				MW2: md.MW2, VW2: md.VW2, MB2: md.MB2, VB2: md.VB2,
				MW3: md.MW3, VW3: md.VW3, MB3: md.MB3, VB3: md.VB3,

				Step: md.Step,

				LearningRate: md.LearningRate,
				Beta1:        md.Beta1,
				Beta2:        md.Beta2,
				AdamEps:      md.AdamEps,
				WeightDecay:  md.WeightDecay,
				Dropout:      md.Dropout,
				LeakyAlpha:   md.LeakyAlpha,
				GradClip:     md.GradClip,

				NormCount: md.NormCount,
				NormMean:  md.NormMean,
				NormM2:    md.NormM2,

				FeatureImportance: md.FeatureImportance,
				PosCount:          md.PosCount,
				NegCount:          md.NegCount,

				Stats:       md.Stats,
				Version:     md.Version,
				CreatedAt:   md.CreatedAt,
				LastUpdated: md.LastUpdated,
			}
		}
	}

	rand.Seed(time.Now().UnixNano())
	m := &RLModel{
		W1: make2D(InputSize, HiddenSize1),
		B1: make([]float64, HiddenSize1),
		W2: make2D(HiddenSize1, HiddenSize2),
		B2: make([]float64, HiddenSize2),
		W3: make([]float64, HiddenSize2),
		B3: 0,

		MW1: make2D(InputSize, HiddenSize1),
		VW1: make2D(InputSize, HiddenSize1),
		MB1: make([]float64, HiddenSize1),
		VB1: make([]float64, HiddenSize1),

		MW2: make2D(HiddenSize1, HiddenSize2),
		VW2: make2D(HiddenSize1, HiddenSize2),
		MB2: make([]float64, HiddenSize2),
		VB2: make([]float64, HiddenSize2),

		MW3: make([]float64, HiddenSize2),
		VW3: make([]float64, HiddenSize2),

		LearningRate: 0.0015,
		Beta1:        0.9,
		Beta2:        0.999,
		AdamEps:      1e-8,
		WeightDecay:  1e-4,
		Dropout:      0.10,
		LeakyAlpha:   0.05,
		GradClip:     5.0,

		NormMean: make([]float64, InputSize),
		NormM2:   make([]float64, InputSize),

		FeatureImportance: make([]float64, InputSize),

		Version:     ModelVersion,
		CreatedAt:   time.Now(),
		LastUpdated: time.Now(),
	}

	initHe2D(m.W1, InputSize)
	initHe2D(m.W2, HiddenSize1)
	initHe1D(m.W3, HiddenSize2)

	m.Stats.LearningRate = m.LearningRate
	return m
}

func (m *RLModel) Save(path string) error {
	m.LastUpdated = time.Now()
	md := ModelData{
		W1: m.W1, B1: m.B1,
		W2: m.W2, B2: m.B2,
		W3: m.W3, B3: m.B3,

		MW1: m.MW1, VW1: m.VW1, MB1: m.MB1, VB1: m.VB1,
		MW2: m.MW2, VW2: m.VW2, MB2: m.MB2, VB2: m.VB2,
		MW3: m.MW3, VW3: m.VW3, MB3: m.MB3, VB3: m.VB3,

		Step: m.Step,

		LearningRate: m.LearningRate,
		Beta1:        m.Beta1,
		Beta2:        m.Beta2,
		AdamEps:      m.AdamEps,
		WeightDecay:  m.WeightDecay,
		Dropout:      m.Dropout,
		LeakyAlpha:   m.LeakyAlpha,
		GradClip:     m.GradClip,

		NormCount: m.NormCount,
		NormMean:  m.NormMean,
		NormM2:    m.NormM2,

		FeatureImportance: m.FeatureImportance,
		PosCount:          m.PosCount,
		NegCount:          m.NegCount,

		Stats:       m.Stats,
		Version:     m.Version,
		CreatedAt:   m.CreatedAt,
		LastUpdated: m.LastUpdated,
	}

	data, err := json.MarshalIndent(md, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (m *RLModel) Predict(features *analyzer.BinaryFeatures) float64 {
	x := m.featuresToVector(features)
	xn := m.normalize(x)
	p, _ := m.forward(xn, false)
	return p
}

func (m *RLModel) Train(features *analyzer.BinaryFeatures, isMalicious bool, reward float64) {
	x := m.featuresToVector(features)

	m.updateNorm(x)
	xn := m.normalize(x)

	const smooth = 0.02
	y := smooth
	if isMalicious {
		y = 1.0 - smooth
	}

	if isMalicious {
		m.PosCount++
	} else {
		m.NegCount++
	}
	posW := float64(m.NegCount+1) / float64(m.PosCount+1)
	if posW < 1.0 {
		posW = 1.0
	}
	if posW > 10.0 {
		posW = 10.0
	}
	sampleW := 1.0
	if isMalicious {
		sampleW = posW
	}

	p, c := m.forward(xn, true)

	dz3 := (p - y) * sampleW

	ga2 := make([]float64, HiddenSize2)
	for j := 0; j < HiddenSize2; j++ {
		ga2[j] = dz3 * m.W3[j]
	}

	for j := 0; j < HiddenSize2; j++ {
		ga2[j] *= c.drop2Scale[j]
	}

	dz2 := make([]float64, HiddenSize2)
	for j := 0; j < HiddenSize2; j++ {
		dz2[j] = ga2[j] * leakyReluDeriv(c.z2[j], m.LeakyAlpha)
	}

	ga1 := make([]float64, HiddenSize1)
	for i := 0; i < HiddenSize1; i++ {
		sum := 0.0
		for j := 0; j < HiddenSize2; j++ {
			sum += dz2[j] * m.W2[i][j]
		}
		ga1[i] = sum
	}

	for i := 0; i < HiddenSize1; i++ {
		ga1[i] *= c.drop1Scale[i]
	}

	dz1 := make([]float64, HiddenSize1)
	for i := 0; i < HiddenSize1; i++ {
		dz1[i] = ga1[i] * leakyReluDeriv(c.z1[i], m.LeakyAlpha)
	}

	gW3 := make([]float64, HiddenSize2)
	for j := 0; j < HiddenSize2; j++ {
		gW3[j] = dz3 * c.a2[j]
	}
	gB3 := dz3

	gW2 := make2D(HiddenSize1, HiddenSize2)
	gB2 := make([]float64, HiddenSize2)
	for j := 0; j < HiddenSize2; j++ {
		gB2[j] = dz2[j]
		for i := 0; i < HiddenSize1; i++ {
			gW2[i][j] = dz2[j] * c.a1[i]
		}
	}

	gW1 := make2D(InputSize, HiddenSize1)
	gB1 := make([]float64, HiddenSize1)
	for j := 0; j < HiddenSize1; j++ {
		gB1[j] = dz1[j]
		for i := 0; i < InputSize; i++ {
			gW1[i][j] = dz1[j] * xn[i]
		}
	}

	for i := 0; i < InputSize; i++ {
		dxi := 0.0
		for j := 0; j < HiddenSize1; j++ {
			dxi += dz1[j] * m.W1[i][j]
		}
		m.FeatureImportance[i] += math.Abs(dxi)
	}

	clip2DInPlace(gW1, m.GradClip)
	clip1DInPlace(gB1, m.GradClip)
	clip2DInPlace(gW2, m.GradClip)
	clip1DInPlace(gB2, m.GradClip)
	clip1DInPlace(gW3, m.GradClip)
	gB3 = clipScalar(gB3, m.GradClip)

	m.Step++
	t := float64(m.Step)

	adamw2D(m.W1, gW1, m.MW1, m.VW1, m.LearningRate, m.Beta1, m.Beta2, m.AdamEps, m.WeightDecay, t)
	adamw1D(m.B1, gB1, m.MB1, m.VB1, m.LearningRate, m.Beta1, m.Beta2, m.AdamEps, 0.0, t)

	adamw2D(m.W2, gW2, m.MW2, m.VW2, m.LearningRate, m.Beta1, m.Beta2, m.AdamEps, m.WeightDecay, t)
	adamw1D(m.B2, gB2, m.MB2, m.VB2, m.LearningRate, m.Beta1, m.Beta2, m.AdamEps, 0.0, t)

	adamw1D(m.W3, gW3, m.MW3, m.VW3, m.LearningRate, m.Beta1, m.Beta2, m.AdamEps, m.WeightDecay, t)
	m.B3 = adamwScalar(m.B3, gB3, &m.MB3, &m.VB3, m.LearningRate, m.Beta1, m.Beta2, m.AdamEps, t)

	m.Stats.TrainingSamples++
	m.Stats.TotalReward += reward
	m.Stats.AverageReward = m.Stats.TotalReward / float64(m.Stats.TrainingSamples)

	correct := (p > 0.5 && isMalicious) || (p <= 0.5 && !isMalicious)
	if correct {
		m.Stats.CorrectPredictions++
		if isMalicious {
			m.Stats.TruePositives++
		} else {
			m.Stats.TrueNegatives++
		}
	} else {
		m.Stats.IncorrectPredictions++
		if isMalicious {
			m.Stats.FalseNegatives++
		} else {
			m.Stats.FalsePositives++
		}
	}

	acc := float64(m.Stats.CorrectPredictions) / float64(m.Stats.TrainingSamples)
	if acc > m.Stats.BestAccuracy {
		m.Stats.BestAccuracy = acc
	}
	if m.Stats.TrainingSamples%100 == 0 {
		m.Stats.EpochCount++
	}
	m.Stats.LearningRate = m.LearningRate
}

func (m *RLModel) GetStats() ModelStats {
	m.Stats.LearningRate = m.LearningRate
	return m.Stats
}

type FeatureImportance struct {
	Index      int
	Importance float64
	Name       string
}

func (m *RLModel) GetTopFeatures(n int) []FeatureImportance {
	names := []string{
		"Entropy", "FileSize", "OverlaySize", "OverlayRatio",
		"SectionCount", "ImportCount", "ExportCount", "ResourceCount", "TLSCallbackCount",
		"HasDebugInfo", "HasOverlay", "HasRelocations", "HasResources", "HasTLS", "IsDLL", "Is64Bit",
		"HasNXCompat", "HasDEP", "HasASLR", "HasSEH", "HasCFG", "IsSigned",
		"SuspiciousAPIs", "SuspiciousStrings", "PackedIndicator", "WritableExecSections",
		"SuspiciousSections", "AnomalousTimestamp", "LowImportCount",
		"CodeSectionEntropy", "DataSectionEntropy", "MaxSectionEntropy", "MinSectionEntropy",
		"AvgSectionEntropy", "SectionEntropyStdDev",
		"CodeToDataRatio", "ImportToExportRatio", "ResourceSizeRatio",
		"UniqueDLLCount", "ImportDensity", "SuspiciousDLLs",
		"ASCIIStringCount", "UnicodeStringCount", "URLCount", "IPAddressCount",
		"RegistryKeyCount", "FilePathCount",
		"CompileTimestamp", "TimestampAge",
		"EPSectionEntropy", "EPInLastSection", "SectionNameEntropy",
	}

	fi := make([]FeatureImportance, InputSize)
	for i := 0; i < InputSize; i++ {
		name := fmt.Sprintf("Feature_%d", i)
		if i < len(names) {
			name = names[i]
		}
		fi[i] = FeatureImportance{
			Index:      i,
			Importance: m.FeatureImportance[i],
			Name:       name,
		}
	}

	if n > len(fi) {
		n = len(fi)
	}
	for i := 0; i < n; i++ {
		best := i
		for j := i + 1; j < len(fi); j++ {
			if fi[j].Importance > fi[best].Importance {
				best = j
			}
		}
		fi[i], fi[best] = fi[best], fi[i]
	}
	return fi[:n]
}

type fwdCache struct {
	z1 []float64
	a1 []float64
	z2 []float64
	a2 []float64

	drop1Scale []float64
	drop2Scale []float64
}

func (m *RLModel) forward(x []float64, training bool) (float64, *fwdCache) {
	c := &fwdCache{
		z1:         make([]float64, HiddenSize1),
		a1:         make([]float64, HiddenSize1),
		z2:         make([]float64, HiddenSize2),
		a2:         make([]float64, HiddenSize2),
		drop1Scale: make([]float64, HiddenSize1),
		drop2Scale: make([]float64, HiddenSize2),
	}

	for j := 0; j < HiddenSize1; j++ {
		sum := m.B1[j]
		for i := 0; i < InputSize; i++ {
			sum += x[i] * m.W1[i][j]
		}
		c.z1[j] = sum
		c.a1[j] = leakyRelu(sum, m.LeakyAlpha)
	}

	if training && m.Dropout > 0 {
		scale := 1.0 / (1.0 - m.Dropout)
		for j := 0; j < HiddenSize1; j++ {
			if rand.Float64() < m.Dropout {
				c.drop1Scale[j] = 0
			} else {
				c.drop1Scale[j] = scale
			}
			c.a1[j] *= c.drop1Scale[j]
		}
	} else {
		for j := 0; j < HiddenSize1; j++ {
			c.drop1Scale[j] = 1.0
		}
	}

	for j := 0; j < HiddenSize2; j++ {
		sum := m.B2[j]
		for i := 0; i < HiddenSize1; i++ {
			sum += c.a1[i] * m.W2[i][j]
		}
		c.z2[j] = sum
		c.a2[j] = leakyRelu(sum, m.LeakyAlpha)
	}

	if training && m.Dropout > 0 {
		scale := 1.0 / (1.0 - m.Dropout)
		for j := 0; j < HiddenSize2; j++ {
			if rand.Float64() < m.Dropout {
				c.drop2Scale[j] = 0
			} else {
				c.drop2Scale[j] = scale
			}
			c.a2[j] *= c.drop2Scale[j]
		}
	} else {
		for j := 0; j < HiddenSize2; j++ {
			c.drop2Scale[j] = 1.0
		}
	}

	logit := m.B3
	for j := 0; j < HiddenSize2; j++ {
		logit += c.a2[j] * m.W3[j]
	}
	return sigmoid(logit), c
}

func (m *RLModel) updateNorm(x []float64) {
	m.NormCount++
	n := float64(m.NormCount)
	for i := 0; i < InputSize; i++ {
		delta := x[i] - m.NormMean[i]
		m.NormMean[i] += delta / n
		delta2 := x[i] - m.NormMean[i]
		m.NormM2[i] += delta * delta2
	}
}

func (m *RLModel) normalize(x []float64) []float64 {
	out := make([]float64, len(x))
	if m.NormCount < 2 {
		copy(out, x)
		return out
	}
	for i := 0; i < InputSize; i++ {
		variance := m.NormM2[i] / float64(m.NormCount-1)
		if variance < 1e-12 {
			variance = 1e-12
		}
		std := math.Sqrt(variance)
		z := (x[i] - m.NormMean[i]) / std
		if z > 10 {
			z = 10
		} else if z < -10 {
			z = -10
		}
		out[i] = z
	}
	return out
}

func (m *RLModel) featuresToVector(f *analyzer.BinaryFeatures) []float64 {
	return []float64{
		f.Entropy / 8.0,
		float64(f.FileSize) / 10000000.0,
		float64(f.OverlaySize) / 1000000.0,
		f.OverlayRatio,

		float64(f.SectionCount) / 20.0,
		float64(f.ImportCount) / 500.0,
		float64(f.ExportCount) / 100.0,
		float64(f.ResourceCount) / 100.0,
		float64(f.TLSCallbackCount) / 10.0,
		float64(f.HasDebugInfo),
		float64(f.HasOverlay),
		float64(f.HasRelocations),
		float64(f.HasResources),
		float64(f.HasTLS),
		float64(f.IsDLL),
		float64(f.Is64Bit),

		float64(f.HasNXCompat),
		float64(f.HasDEP),
		float64(f.HasASLR),
		float64(f.HasSEH),
		float64(f.HasCFG),
		float64(f.IsSigned),

		float64(f.SuspiciousAPIs) / 50.0,
		float64(f.SuspiciousStrings) / 20.0,
		float64(f.PackedIndicator),
		float64(f.WritableExecutableSections) / 5.0,
		float64(f.SuspiciousSections) / 5.0,
		float64(f.AnomalousTimestamp),
		float64(f.LowImportCount),

		f.CodeSectionEntropy / 8.0,
		f.DataSectionEntropy / 8.0,
		f.MaxSectionEntropy / 8.0,
		f.MinSectionEntropy / 8.0,
		f.AvgSectionEntropy / 8.0,
		f.SectionEntropyStdDev / 4.0,

		math.Min(f.CodeToDataRatio, 10.0) / 10.0,
		math.Min(f.ImportToExportRatio, 100.0) / 100.0,
		f.ResourceSizeRatio,

		float64(f.UniqueDLLCount) / 50.0,
		f.ImportDensity / 10.0,
		float64(f.SuspiciousDLLs) / 10.0,

		float64(f.ASCIIStringCount) / 1000.0,
		float64(f.UnicodeStringCount) / 1000.0,
		float64(f.URLCount) / 10.0,
		float64(f.IPAddressCount) / 10.0,
		float64(f.RegistryKeyCount) / 20.0,
		float64(f.FilePathCount) / 50.0,

		float64(f.CompileTimestamp) / 1000000000.0,
		f.TimestampAge / 3650.0,

		f.EPSectionEntropy / 8.0,
		float64(f.EPInLastSection),
		f.SectionNameEntropy / 5.0,
	}
}

func make2D(r, c int) [][]float64 {
	m := make([][]float64, r)
	for i := range m {
		m[i] = make([]float64, c)
	}
	return m
}

func initHe2D(w [][]float64, fanIn int) {
	std := math.Sqrt(2.0 / float64(fanIn))
	for i := range w {
		for j := range w[i] {
			w[i][j] = rand.NormFloat64() * std
		}
	}
}

func initHe1D(w []float64, fanIn int) {
	std := math.Sqrt(2.0 / float64(fanIn))
	for i := range w {
		w[i] = rand.NormFloat64() * std
	}
}

func leakyRelu(x, a float64) float64 {
	if x >= 0 {
		return x
	}
	return a * x
}

func leakyReluDeriv(x, a float64) float64 {
	if x >= 0 {
		return 1.0
	}
	return a
}

func sigmoid(x float64) float64 {
	if x > 20 {
		return 1
	}
	if x < -20 {
		return 0
	}
	return 1.0 / (1.0 + math.Exp(-x))
}

func clipScalar(x, clip float64) float64 {
	if clip <= 0 {
		return x
	}
	if x > clip {
		return clip
	}
	if x < -clip {
		return -clip
	}
	return x
}

func clip1DInPlace(g []float64, clip float64) {
	if clip <= 0 {
		return
	}
	for i := range g {
		g[i] = clipScalar(g[i], clip)
	}
}

func clip2DInPlace(g [][]float64, clip float64) {
	if clip <= 0 {
		return
	}
	for i := range g {
		for j := range g[i] {
			g[i][j] = clipScalar(g[i][j], clip)
		}
	}
}

func adamwScalar(param, grad float64, m, v *float64, lr, b1, b2, eps, t float64) float64 {
	*m = b1*(*m) + (1-b1)*grad
	*v = b2*(*v) + (1-b2)*grad*grad
	mhat := (*m) / (1 - math.Pow(b1, t))
	vhat := (*v) / (1 - math.Pow(b2, t))
	return param - lr*mhat/(math.Sqrt(vhat)+eps)
}

func adamw1D(p, g, m, v []float64, lr, b1, b2, eps, wd, t float64) {
	b1t := 1 - math.Pow(b1, t)
	b2t := 1 - math.Pow(b2, t)
	for i := range p {
		if wd != 0 {
			p[i] -= lr * wd * p[i]
		}
		m[i] = b1*m[i] + (1-b1)*g[i]
		v[i] = b2*v[i] + (1-b2)*g[i]*g[i]
		mhat := m[i] / b1t
		vhat := v[i] / b2t
		p[i] -= lr * mhat / (math.Sqrt(vhat) + eps)
	}
}

func adamw2D(p, g, m, v [][]float64, lr, b1, b2, eps, wd, t float64) {
	b1t := 1 - math.Pow(b1, t)
	b2t := 1 - math.Pow(b2, t)
	for i := range p {
		for j := range p[i] {
			if wd != 0 {
				p[i][j] -= lr * wd * p[i][j]
			}
			m[i][j] = b1*m[i][j] + (1-b1)*g[i][j]
			v[i][j] = b2*v[i][j] + (1-b2)*g[i][j]*g[i][j]
			mhat := m[i][j] / b1t
			vhat := v[i][j] / b2t
			p[i][j] -= lr * mhat / (math.Sqrt(vhat) + eps)
		}
	}
}
