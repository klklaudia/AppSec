package appsec.safe.registration;

import java.util.List;

public record ApiResponse(String message, List<String> errors) {}
