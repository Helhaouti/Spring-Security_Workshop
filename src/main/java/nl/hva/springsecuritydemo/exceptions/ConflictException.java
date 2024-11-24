package nl.hva.springsecuritydemo.exceptions;

public class ConflictException extends RuntimeException {

  public ConflictException(String message) {
    super(message);
  }

}
