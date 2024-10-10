#include <ntifs.h>
#include <ntddk.h>
#define PROCESS_TERMINATE (0x0001) 
#define IOCTL_GET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS IrpCreateHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	// Completa la solicitud de creación
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_MJ_CREATE handled\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ProcessId = 0;
	PEPROCESS Process;
	HANDLE ProcessHandle;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IOCTL\n");

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_GET_PID:
		ProcessId = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ProcessId: %d\n", ProcessId);

		status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
		if (NT_SUCCESS(status)) {
			status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE, *PsProcessType, KernelMode, &ProcessHandle);

			if (NT_SUCCESS(status)) {
				KeAttachProcess((PRKPROCESS)Process);
				ZwTerminateProcess(ProcessHandle, 0);
				KeDetachProcess();
				ZwClose(ProcessHandle);
				ObDereferenceObject(Process);
			}
			else {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to open process: %x\n", status);
			}
		}
		else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to lookup process: %x\n", status);
		}
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytes;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	// Delete Symbolic Link
	UNICODE_STRING dos;
	RtlInitUnicodeString(&dos, L"\\DosDevices\\MyDriver");
	IoDeleteSymbolicLink(&dos);

	// Delete Device
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Unloaded\n");
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	

	// Create Device
	UNICODE_STRING dev, dos;
	RtlInitUnicodeString(&dev, L"\\Device\\MyDriver");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\MyDriver");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create device: %x\n", status);
		return status;
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Device Created\n");
	}

	// Create Symbolic Link
	RtlInitUnicodeString(&dos, L"\\DosDevices\\MyDriver");
	// First delete the symbolic link if it already exists
	IoDeleteSymbolicLink(&dos);
	status = IoCreateSymbolicLink(&dos, &dev);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create symbolic link: %x\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Symbolic Link Created\n");
	}

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateHandler;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Loaded\n");

	return STATUS_SUCCESS;
}