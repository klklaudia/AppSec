package appsec.safe.common;

import java.util.List;

public record ApiResponse(String message, List<String> errors) {}
