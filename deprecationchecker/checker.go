// Package imagechecker provides a function to check for deprecated CS images.
package imagechecker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"google3/third_party/golang/cloud_google_com/go/compute/metadata/v/v0/metadata"
	"google.golang.org/api/compute/v1"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
)

const (
	sourceImageProject  = "confidential-space-images"
	deprecationValueFmt = "2006-01-02"
)

// CS Images have the format confidential-space-.*.
var prodImageNameRegex = regexp.MustCompile(`^confidential-space-.*`)

// VMInfo represents the information logged about an VM instance of note.
type VMInfo struct {
	Name            string `json:"instance_name"`
	Zone            string `json:"instance_zone"`
	ImageName       string `json:"image_name"`
	DeprecationDate string `json:"image_deprecation_date,omitempty"`
	ObsoleteDate    string `json:"image_obsolete_date,omitempty"`
}

// VMList represents a list of notable VMs and their relevance.
type VMList struct {
	Description string   `json:"description"`
	Instances   []VMInfo `json:"instances"`
}

// LogPayload is the payload for Cloud Logs written by this job.
type LogPayload struct {
	Message            string  `json:"message"`
	Obsolete           *VMList `json:"vms_obsolete"`
	ObsoleteWarning    *VMList `json:"vms_obsolete_warning"`
	Deprecated         *VMList `json:"vms_deprecated"`
	DeprecationWarning *VMList `json:"vms_deprecation_warning"`
}

// LogEntry represents a Cloud Logging entry.
type LogEntry struct {
	Message   string      `json:"message"`
	Severity  string      `json:"severity"` // Special field for Cloud Logging.
	Payload   *LogPayload `json:"payload,omitempty"`
	ProjectID string      `json:"projectId"`
}

func init() {
	log.SetFlags(0)
	functions.HTTP("DeprecationCheck", checkForDeprecations)
}

func checkForDeprecations(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Retrieve project ID.
	projectID, err := metadata.ProjectIDWithContext(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get project ID from metadata server: %v", err)
		logError(projectID, errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}
	slog.Info(fmt.Sprintf("Checking for project: %s", projectID))

	// Configure compute service.
	computeService, err := compute.NewService(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to create compute service: %v", err)
		logError(projectID, msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	var obsoleteVMs []VMInfo           // Will contain VMs whose images are obsolete.
	var obsoleteWarningVMs []VMInfo    // Will contain VMs using an image that will be obsolete within a month.
	var deprecatedVMs []VMInfo         // Will contain VMs whose images are deprecated.
	var deprecationWarningVMs []VMInfo // Will contain VMs using an image that will be deprecated within a month.
	now := time.Now()

	pageFunc := instancesPageFunc(ctx, projectID, &obsoleteVMs, &obsoleteWarningVMs, &deprecatedVMs, &deprecationWarningVMs, now, computeService)
	if err = computeService.Instances.AggregatedList(projectID).Pages(ctx, pageFunc); err != nil {
		msg := fmt.Sprintf("Failed to list instances: %v", err)
		logError(projectID, msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	if len(obsoleteVMs) == 0 && len(obsoleteWarningVMs) == 0 && len(deprecatedVMs) == 0 && len(deprecationWarningVMs) == 0 {
		returnmsg := "No VMs using obsolete or deprecated images found."
		logEntry := LogEntry{
			Message:   "Confidential Space Image Deprecation Alert - No Issues Detected",
			Severity:  "INFO",
			ProjectID: projectID,
			Payload:   &LogPayload{Message: returnmsg},
		}
		writeLog(logEntry)

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(returnmsg))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to write HTTP response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	respPayload := &LogPayload{
		Message: "The following instances are using Confidential Space images that are obsolete, deprecated, or will be obsolete/deprecated soon. Obsolete and deprecated images are no longer maintained and scanned for vulnerabilities. Please review these instances and update their boot images as needed.",
	}

	if len(obsoleteVMs) > 0 {
		respPayload.Obsolete = &VMList{
			Description: "Instances using CS images that are obsolete.",
			Instances:   obsoleteVMs,
		}
	}
	if len(obsoleteWarningVMs) > 0 {
		respPayload.ObsoleteWarning = &VMList{
			Description: "Instances using CS images that will be obsolete within a month.",
			Instances:   obsoleteWarningVMs,
		}
	}
	if len(deprecatedVMs) > 0 {
		respPayload.Deprecated = &VMList{
			Description: "Instances using CS images that are deprecated.",
			Instances:   deprecatedVMs,
		}
	}
	if len(deprecationWarningVMs) > 0 {
		respPayload.DeprecationWarning = &VMList{
			Description: "Instances using CS images that will be deprecated within a month.",
			Instances:   deprecationWarningVMs,
		}
	}

	entry := LogEntry{
		Message:   "Confidential Space Image Deprecation Alert",
		Severity:  "WARNING",
		ProjectID: projectID,
		Payload:   respPayload,
	}

	writeLog(entry)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(respPayload)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to write HTTP response: %v", err), http.StatusInternalServerError)
		return
	}
}

func instancesPageFunc(ctx context.Context, projectID string, obsoleteVMs *[]VMInfo, obsoleteWarningVMs *[]VMInfo, deprecatedVMs *[]VMInfo, deprecationWarningVMs *[]VMInfo, now time.Time, computeService *compute.Service) func(list *compute.InstanceAggregatedList) error {
	return func(list *compute.InstanceAggregatedList) error {
		for _, instanceList := range list.Items {
			for _, instances := range instanceList.Instances {
				sourceImage, err := getSourceImage(ctx, projectID, instances, computeService)
				if err != nil {
					slog.Warn(fmt.Sprintf("Failed to get source image for instance %s: %v", instances.Name, err))
					continue
				}

				// Skip instance if not using a CS prod image.
				imageProject, imageName := parseImage(sourceImage)
				if imageProject != sourceImageProject || !prodImageNameRegex.MatchString(imageName) {
					continue
				}

				// Get deprecation status ("deprecate-on" / "obsolete-on" / state settings).
				depStatus, err := getDeprecationStatus(ctx, imageProject, imageName, computeService)
				if err != nil {
					slog.Error(fmt.Sprintf("Failed to get deprecation status for image %s in project %s: %v", imageName, imageProject, err))
					continue
				}
				if depStatus == nil {
					continue
				}

				vm := VMInfo{
					Name:      instances.Name,
					Zone:      getResourceName(instances.Zone),
					ImageName: imageName,
				}

				var depTime, obsTime time.Time
				if depStatus.Deprecated != "" {
					depTime, err = parseDeprecationDate(depStatus.Deprecated)
					if err != nil {
						slog.Error(fmt.Sprintf("Failed to parse deprecation date %s for image %s in project %s: %v", depStatus.Deprecated, imageName, imageProject, err))
						continue
					}
					vm.DeprecationDate = depTime.Format(deprecationValueFmt)
				}

				if depStatus.Obsolete != "" {
					obsTime, err = parseDeprecationDate(depStatus.Obsolete)
					if err != nil {
						slog.Error(fmt.Sprintf("Failed to parse obsolete date %s for image %s in project %s: %v", depStatus.Obsolete, imageName, imageProject, err))
						continue
					}
					vm.ObsoleteDate = obsTime.Format(deprecationValueFmt)
				}

				// Determine whether instance image is obsolete, upcoming obsolete, deprecated, or upcoming deprecated.
				if depStatus.State == "OBSOLETE" || (!obsTime.IsZero() && isPast(obsTime, now)) {
					*obsoleteVMs = append(*obsoleteVMs, vm)
				} else if !obsTime.IsZero() && isWarning(obsTime, now) {
					*obsoleteWarningVMs = append(*obsoleteWarningVMs, vm)
				} else if depStatus.State == "DEPRECATED" || (!depTime.IsZero() && isPast(depTime, now)) {
					*deprecatedVMs = append(*deprecatedVMs, vm)
				} else if !depTime.IsZero() && isWarning(depTime, now) {
					*deprecationWarningVMs = append(*deprecationWarningVMs, vm)
				}
			}
		}

		return nil
	}
}

func getSourceImage(ctx context.Context, projectID string, instance *compute.Instance, service *compute.Service) (string, error) {
	for _, disk := range instance.Disks {
		// Only check boot disk.
		if disk.Boot {
			// Retrieve source image for disk.
			diskName := getResourceName(disk.Source)
			zone := getResourceName(instance.Zone)

			d, err := service.Disks.Get(projectID, zone, diskName).Context(ctx).Do()
			if err != nil {
				slog.Warn(fmt.Sprintf("Failed to get details for disk %s in zone %s: %v", diskName, zone, err))
				continue
			}

			if d.SourceImage != "" {
				return d.SourceImage, nil
			}
		}
	}

	return "", fmt.Errorf("no suitable source image name found for instance %s", instance.Name)
}

func getDeprecationStatus(ctx context.Context, imageProject, imageName string, service *compute.Service) (*compute.DeprecationStatus, error) {
	image, err := service.Images.Get(imageProject, imageName).Context(ctx).Do()
	if err != nil {
		slog.Warn(fmt.Sprintf("Failed to get details for image %s in project %s: %v", imageName, imageProject, err))
		return nil, err
	}

	if image.Deprecated == nil || (image.Deprecated.Deprecated == "" && image.Deprecated.Obsolete == "" && image.Deprecated.State == "") {
		// Skip if no deprecation/obsolete setting.
		slog.Warn(fmt.Sprintf("Image %s in project %s has no deprecate-on or obsolete-on setting", imageName, imageProject))
		return nil, nil
	}

	return image.Deprecated, nil
}

func parseDeprecationDate(dateStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02",
		"2006-01",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse %q as a valid deprecation date", dateStr)
}

func isPast(obsTime time.Time, now time.Time) bool {
	return !obsTime.After(now)
}

func isWarning(targetTime time.Time, now time.Time) bool {
	warningWindowEnd := now.AddDate(0, 1, 0)
	return targetTime.After(now) && !targetTime.After(warningWindowEnd)
}

func parseImage(image string) (string, string) {
	parts := strings.Split(image, "/")

	var project, imageName string
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			project = parts[i+1]
		} else if part == "images" && i+1 < len(parts) {
			imageName = parts[i+1]
		}
	}

	slog.Info(fmt.Sprintf("Source image project: %s, name: %s", project, imageName))

	return project, imageName
}

// getResourceName extracts the last part of a GCP resource URL.
func getResourceName(url string) string {
	parts := strings.Split(url, "/")
	return parts[len(parts)-1]
}

func writeLog(entry LogEntry) {
	jsonData, err := json.Marshal(entry)
	if err != nil {
		slog.Warn(fmt.Sprintf("Error marshaling final log: %v", err))
		slog.Warn(fmt.Sprintf("Log contents: %v", entry))
		return
	}

	fmt.Println(string(jsonData))
}

func logError(projectID, errMsg string) {
	entry := LogEntry{
		Message:   "Confidential Space Image Deprecation Alert - Job Failed",
		Severity:  "ERROR",
		ProjectID: projectID,
		Payload: &LogPayload{
			Message: errMsg,
		},
	}

	writeLog(entry)
}
