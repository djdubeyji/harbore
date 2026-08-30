package container

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

type Manager struct {
	docker      *client.Client
	workerImage string
	network     string
	workerToken string
	orchestratorURL string
}

func New(workerImage, network, workerToken, orchestratorURL string) (*Manager, error) {
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}

	return &Manager{
		docker:          cli,
		workerImage:     workerImage,
		network:         network,
		workerToken:     workerToken,
		orchestratorURL: orchestratorURL,
	}, nil
}

// SpawnWorker starts a new worker container for a specific job.
func (m *Manager) SpawnWorker(ctx context.Context, jobID, scanID string) (string, error) {
	containerName := fmt.Sprintf("harbore-worker-%s", jobID[:8])

	cfg := &container.Config{
		Image: m.workerImage,
		Env: []string{
			"ORCHESTRATOR_URL=" + m.orchestratorURL,
			"WORKER_TOKEN=" + m.workerToken,
			"JOB_ID=" + jobID,
			"SCAN_ID=" + scanID,
		},
		Labels: map[string]string{
			"harbore.managed": "true",
			"harbore.scan_id": scanID,
			"harbore.job_id":  jobID,
		},
	}

	hostCfg := &container.HostConfig{
		AutoRemove:  true,
		NetworkMode: container.NetworkMode(m.network),
		Resources: container.Resources{
			Memory:   512 * 1024 * 1024, // 512MB
			NanoCPUs: 1_000_000_000,     // 1 CPU
		},
		// Security: no privileged, no host network
		SecurityOpt: []string{"no-new-privileges:true"},
	}

	netCfg := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			m.network: {},
		},
	}

	resp, err := m.docker.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, containerName)
	if err != nil {
		return "", fmt.Errorf("container create: %w", err)
	}

	if err := m.docker.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		// Clean up on start failure
		_ = m.docker.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("container start: %w", err)
	}

	log.Printf("[container] spawned worker container=%s job=%s", resp.ID[:12], jobID[:8])
	return resp.ID, nil
}

// StopWorker force-stops a running worker container.
func (m *Manager) StopWorker(ctx context.Context, containerID string) error {
	timeout := 10 // seconds
	if err := m.docker.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("stop container: %w", err)
	}
	log.Printf("[container] stopped worker container=%s", containerID[:12])
	return nil
}

// CountActiveWorkers returns how many Harbore worker containers are running.
func (m *Manager) CountActiveWorkers(ctx context.Context) (int, error) {
	f := filters.NewArgs()
	f.Add("label", "harbore.managed=true")
	f.Add("status", "running")

	containers, err := m.docker.ContainerList(ctx, container.ListOptions{Filters: f})
	if err != nil {
		return 0, fmt.Errorf("list containers: %w", err)
	}
	return len(containers), nil
}

// StopScanWorkers stops all workers belonging to a specific scan.
func (m *Manager) StopScanWorkers(ctx context.Context, scanID string) error {
	f := filters.NewArgs()
	f.Add("label", "harbore.scan_id="+scanID)
	f.Add("status", "running")

	containers, err := m.docker.ContainerList(ctx, container.ListOptions{Filters: f})
	if err != nil {
		return err
	}

	for _, c := range containers {
		timeout := 5
		if err := m.docker.ContainerStop(ctx, c.ID, container.StopOptions{Timeout: &timeout}); err != nil {
			log.Printf("[container] warn: failed to stop container=%s: %v", c.ID[:12], err)
		}
	}

	log.Printf("[container] stopped %d workers for scan=%s", len(containers), scanID[:8])
	return nil
}

// PullImage ensures the worker image is available.
func (m *Manager) PullImage(ctx context.Context) error {
	out, err := m.docker.ImagePull(ctx, m.workerImage, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("image pull %s: %w", m.workerImage, err)
	}
	defer out.Close()
	_, _ = io.Copy(io.Discard, out)
	return nil
}

// Ping checks Docker daemon connectivity.
func (m *Manager) Ping(ctx context.Context) error {
	_, err := m.docker.Ping(ctx)
	return err
}

func (m *Manager) Close() error {
	return m.docker.Close()
}
