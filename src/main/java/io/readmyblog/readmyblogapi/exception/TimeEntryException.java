package io.readmyblog.readmyblogapi.exception;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.Map;

@Builder
@JsonIgnoreProperties(value = {"suppressed", "localizedMessage", "message", "cause", "stackTrace", "httpStatus"},
        ignoreUnknown = true)
@Getter
public class TimeEntryException extends RuntimeException {

    private static final long serialVersionUID = -3072524130772215009L;

    private final HttpStatus httpStatus;
    private final String code;
    private final transient Map<String, Object> details;

    public TimeEntryException() {
        this(HttpStatus.INTERNAL_SERVER_ERROR, "internal.error", null, null);
    }

    public TimeEntryException(HttpStatus httpStatus, String code) {
        this(httpStatus, code, null, null);
    }

    public TimeEntryException(HttpStatus httpStatus, String code, Map<String, Object> details) {
        this(httpStatus, code, details, null);
    }

    public TimeEntryException(HttpStatus httpStatus, String code, Map<String, Object> details, Throwable cause) {
        super(code, cause);
        this.httpStatus = httpStatus;
        this.code = code;
        this.details = details;
    }
}
