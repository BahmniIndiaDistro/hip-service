using System;
using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.Patient.Database;

namespace In.ProjectEKA.HipService.Patient.jobs;

public class CleanPatientQueueJob
{
    private readonly PatientContext patientContext;
    private readonly OpenMrsConfiguration openMrsConfiguration;

    public CleanPatientQueueJob(PatientContext patientContext, OpenMrsConfiguration openMrsConfiguration)
    {
        this.patientContext = patientContext;
        this.openMrsConfiguration = openMrsConfiguration;
    }

    public void CleanPatientQueue()
    {
        List<PatientQueue> oldEntries = patientContext.PatientQueue.ToList().FindAll(
            patient => DateTime.Now.Subtract(DateTime.Parse(patient.DateTimeStamp)).TotalMinutes >
                       openMrsConfiguration.PatientQueueTimeLimit
        );

        patientContext.PatientQueue.RemoveRange(oldEntries);
        patientContext.SaveChanges();

        Log.Information($"Deleted {oldEntries.Count} old patient queue  at {DateTime.UtcNow}");
    }
}