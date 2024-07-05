package dev.webProject.VoluntHeart.DTO;

import dev.webProject.VoluntHeart.Models.Location;
import lombok.Data;

@Data
public class PostDataDTO {

    private String content;
    private String[] images ;
    private String[] videos;
    private Location location;


}
