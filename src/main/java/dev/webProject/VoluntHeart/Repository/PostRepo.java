package dev.webProject.VoluntHeart.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import dev.webProject.VoluntHeart.Models.Posts;
import java.util.List;
import dev.webProject.VoluntHeart.Models.Users.UserModel;

@Repository
public interface PostRepo extends MongoRepository<Posts, String> {

    public Posts findByPostId(String postId);

    public List<Posts> findByCreatedBy(UserModel createdBy);

    public Posts findByUniqueKey(String uniqueKey);

    public List<Posts> findByContentContainingIgnoreCase(String content);

}
